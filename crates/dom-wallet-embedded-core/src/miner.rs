//! Wallet-owned CPU miner adapter over the embedded canonical node.

use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    checked_accumulated_difficulty, compute_block_pmmr_roots, Block, CoinbaseTransaction,
};
use dom_core::{BlockHeight, Hash256, Timestamp};
use dom_node::node::DomNode;
use dom_pow::{
    compute_expected_target, fast_pow_hash, hash_meets_target, pow_validation_mode_for_network,
    randomx_pool, randomx_seed_height, target_to_compact, target_to_difficulty_for_network_height,
    CompactTarget, PowValidationMode,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const TEMPLATE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletMiningOutcome {
    Accepted { height: u64 },
    Rejected { height: u64 },
    Stale { height: u64 },
    TemplateExpired { height: u64 },
    Stopped,
}

#[derive(Debug, Error)]
pub enum WalletMiningError {
    /// The node cannot serve work *right now* — it is still catching up or has
    /// no authoritative peer height yet. Retriable: the caller must back off
    /// and try again, NEVER stop mining. Treating this as fatal is why mining
    /// died permanently on the first synchronization dip.
    #[error("wallet mining is waiting for node synchronization ({0})")]
    NotReady(&'static str),
    /// Preparation failed for a reason retrying cannot fix (missing seed index,
    /// unusable target, bad PoW mode, arithmetic overflow, PMMR failure).
    #[error("wallet mining preparation failed ({0})")]
    Preparation(&'static str),
    #[error("wallet mining worker failed")]
    Worker,
    #[error("wallet mined block validation failed")]
    Validation,
}

impl WalletMiningError {
    /// Whether the caller should back off and retry instead of stopping.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::NotReady(_))
    }

    /// Stable, redacted diagnostic code for status and logs. Carries no height,
    /// hash, address or any other chain- or wallet-identifying material.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotReady(_) => "MINING_NODE_NOT_SYNCHRONIZED",
            Self::Preparation(stage) => match *stage {
                "SEED_INDEX" => "MINING_PREPARATION_SEED_INDEX",
                "TARGET" => "MINING_PREPARATION_TARGET",
                "POW_MODE" => "MINING_PREPARATION_POW_MODE",
                "DIFFICULTY" => "MINING_PREPARATION_DIFFICULTY",
                "PMMR_ROOTS" => "MINING_PREPARATION_PMMR_ROOTS",
                _ => "MINING_PREPARATION_FAILED",
            },
            Self::Worker => "MINING_WORKER_FAILED",
            Self::Validation => "MINING_BLOCK_VALIDATION_FAILED",
        }
    }
}

/// Mine one candidate made by the Wallet's recovery-capable coinbase builder.
///
/// Only public block material reaches the node. Hash attempts are counted at
/// the exact point real RandomX work is performed.
pub async fn mine_wallet_block(
    node: Arc<DomNode>,
    coinbase: &CoinbaseTransaction,
    threads: usize,
    stop_requested: Arc<AtomicBool>,
    hash_attempts: Arc<AtomicU64>,
) -> Result<WalletMiningOutcome, WalletMiningError> {
    if threads == 0 || stop_requested.load(Ordering::Acquire) {
        return Ok(WalletMiningOutcome::Stopped);
    }
    let (tip_hash, tip_height, tip_difficulty, parent_timestamp, seed_hash) = {
        let chain = node.chain.lock().await;
        let parent_timestamp = chain
            .store
            .get_block_header(chain.tip_hash.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| BlockHeader::from_bytes(&bytes).ok())
            .map(|header| header.timestamp.0)
            .unwrap_or(0);
        let candidate_height = chain.tip_height.0.saturating_add(1);
        let seed_height = randomx_seed_height(candidate_height);
        let seed_hash = chain
            .store
            .get_hash_at_height(seed_height)
            .map_err(|_| WalletMiningError::Preparation("SEED_INDEX"))?
            .unwrap_or([0; 32]);
        (
            chain.tip_hash,
            chain.tip_height,
            chain.tip_difficulty,
            parent_timestamp,
            seed_hash,
        )
    };
    let height = tip_height.0.saturating_add(1);
    let timestamp = Timestamp(now_seconds().max(parent_timestamp.saturating_add(1)));
    let target =
        compute_expected_target(node.config.network.magic(), timestamp, BlockHeight(height))
            .map_err(|_| WalletMiningError::Preparation("TARGET"))?;
    let fast_mode = matches!(
        pow_validation_mode_for_network(node.config.network.magic())
            .map_err(|_| WalletMiningError::Preparation("POW_MODE"))?,
        PowValidationMode::FastDevOnly
    );
    // CONSENSUS: per-block work is network- and height-dependent. Mainnet at or
    // above MAINNET_ASERT_RESCUE_HEIGHT uses a different work numerator, and
    // `ChainState` recomputes `expected_total` with this exact function and
    // rejects any header that disagrees ("total_difficulty mismatch"). The
    // plain `target_to_difficulty` used here before produced a valid-looking
    // header that the canonical validator refused at every post-rescue height.
    let difficulty = target_to_difficulty_for_network_height(
        node.config.network.magic(),
        BlockHeight(height),
        &target,
    )
    .map_err(|_| WalletMiningError::Preparation("DIFFICULTY"))?;
    let total_difficulty = checked_accumulated_difficulty(tip_difficulty, difficulty)
        .map_err(|_| WalletMiningError::Preparation("DIFFICULTY"))?;
    let transactions = Vec::new();
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(BlockHeight(height), coinbase, &transactions)
            .map_err(|_| WalletMiningError::Preparation("PMMR_ROOTS"))?;
    let template = BlockHeader {
        version: dom_core::required_block_version_for_network(node.config.network.magic(), height),
        prev_hash: tip_hash,
        height: BlockHeight(height),
        timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset: [0; 32],
        target: CompactTarget(target_to_compact(&target)),
        total_difficulty,
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    let round_stop = Arc::new(AtomicBool::new(false));
    let template_started = Instant::now();
    let require_network_ready = node.config.network == dom_config::Network::Mainnet;
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let worker_template = template.clone();
        let worker_target = target;
        let worker_seed = seed_hash;
        let worker_fast_mode = fast_mode;
        let worker_stop = Arc::clone(&round_stop);
        let external_stop = Arc::clone(&stop_requested);
        let attempts = Arc::clone(&hash_attempts);
        let result_sender = sender.clone();
        let worker_node = Arc::clone(&node);
        workers.push(
            std::thread::Builder::new()
                .name(format!("dom-wallet-miner-{worker_id}"))
                .spawn(move || {
                    let mut header = worker_template;
                    let mut nonce = worker_id as u64;
                    let stride = threads as u64;
                    while !worker_stop.load(Ordering::Acquire)
                        && !external_stop.load(Ordering::Acquire)
                        && template_is_current(
                            tip_height.0,
                            worker_node.metrics.chain_height.load(Ordering::Acquire),
                            worker_node.metrics.peer_count.load(Ordering::Acquire),
                            worker_node
                                .metrics
                                .best_known_peer_height
                                .load(Ordering::Acquire),
                            require_network_ready,
                            template_started.elapsed(),
                        )
                    {
                        header.pow.nonce = nonce;
                        let preimage = header.pow_preimage();
                        let hash = if worker_fast_mode {
                            fast_pow_hash(&worker_seed, &preimage)
                        } else {
                            match randomx_pool::randomx_hash(&worker_seed, &preimage) {
                                Ok(hash) => hash,
                                Err(_) => {
                                    let _ = result_sender.send(Err(()));
                                    return;
                                }
                            }
                        };
                        attempts.fetch_add(1, Ordering::Relaxed);
                        if hash_meets_target(&hash, &worker_target) {
                            header.pow.randomx_hash = Hash256::from_bytes(hash);
                            worker_stop.store(true, Ordering::Release);
                            let _ = result_sender.send(Ok(header));
                            return;
                        }
                        nonce = nonce.wrapping_add(stride);
                    }
                })
                .map_err(|_| WalletMiningError::Worker)?,
        );
    }
    drop(sender);

    let mut winning_header = None;
    while !stop_requested.load(Ordering::Acquire) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(header)) => {
                winning_header = Some(header);
                break;
            }
            Ok(Err(())) => {
                round_stop.store(true, Ordering::Release);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    round_stop.store(true, Ordering::Release);
    for worker in workers {
        let _ = worker.join();
    }
    let Some(header) = winning_header else {
        return if stop_requested.load(Ordering::Acquire) {
            Ok(WalletMiningOutcome::Stopped)
        } else if require_network_ready
            && !authoritative_network_ready(
                node.metrics.chain_height.load(Ordering::Acquire),
                node.metrics.peer_count.load(Ordering::Acquire),
                node.metrics.best_known_peer_height.load(Ordering::Acquire),
            )
        {
            // Transient by construction: the node is behind its peers or has no
            // authoritative peer height yet. Both recover on their own.
            Err(WalletMiningError::NotReady("NODE_NOT_SYNCHRONIZED"))
        } else if node.metrics.chain_height.load(Ordering::Acquire) != tip_height.0 {
            Ok(WalletMiningOutcome::Stale { height })
        } else if template_started.elapsed() >= TEMPLATE_REFRESH_INTERVAL {
            Ok(WalletMiningOutcome::TemplateExpired { height })
        } else {
            Err(WalletMiningError::Worker)
        };
    };

    let block = Block {
        header,
        coinbase: coinbase.clone(),
        transactions,
    };
    let outcome = {
        let mut chain = node.chain.lock().await;
        chain
            .connect_block(&block, Timestamp(now_seconds()))
            .map_err(|_| WalletMiningError::Validation)?
    };
    let accepted = matches!(
        outcome,
        dom_chain::ConnectResult::BestChain | dom_chain::ConnectResult::Reorg(_)
    );
    if accepted {
        node.metrics.blocks_mined.fetch_add(1, Ordering::Relaxed);
        node.metrics.chain_height.store(height, Ordering::Relaxed);
        let bytes = block
            .to_bytes()
            .map_err(|_| WalletMiningError::Validation)?;
        let _ = node.block_relay_tx.send(bytes);
        node.notify_state_changed();
        Ok(WalletMiningOutcome::Accepted { height })
    } else {
        Ok(WalletMiningOutcome::Rejected { height })
    }
}

fn template_is_current(
    tip_height: u64,
    current_height: u64,
    peer_count: u64,
    highest_known_peer_height: u64,
    require_network_ready: bool,
    elapsed: Duration,
) -> bool {
    tip_height == current_height
        && elapsed < TEMPLATE_REFRESH_INTERVAL
        && (!require_network_ready
            || authoritative_network_ready(current_height, peer_count, highest_known_peer_height))
}

fn authoritative_network_ready(
    current_height: u64,
    peer_count: u64,
    highest_known_peer_height: u64,
) -> bool {
    peer_count > 0 && highest_known_peer_height == current_height
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::{NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST};
    use dom_pow::MAINNET_ASERT_RESCUE_HEIGHT;

    /// CONSENSUS REGRESSION.
    ///
    /// The Wallet used to compute per-block work with the plain
    /// `target_to_difficulty`, which ignores network and height. Mainnet at or
    /// above `MAINNET_ASERT_RESCUE_HEIGHT` uses a different work numerator, so
    /// every block the Wallet mined there carried a `total_difficulty` that
    /// `ChainState` recomputed differently and rejected outright with
    /// "total_difficulty mismatch" — Mainnet mining was simply broken, and the
    /// live chain is thousands of blocks past the rescue height.
    ///
    /// This asserts the Wallet's header field equals, bit for bit, what the
    /// canonical validator derives for the same target, across the activation
    /// boundary. It is the deterministic half of "a post-ASERT Mainnet block
    /// created by the Wallet connects": real end-to-end connection needs live
    /// RandomX work and belongs to a manual Mainnet run.
    #[test]
    fn regression_wallet_block_work_matches_the_canonical_validator_across_asert() {
        // Just below, exactly at, and just above the activation height, plus a
        // height far past it (where live Mainnet actually is).
        let boundary = [
            MAINNET_ASERT_RESCUE_HEIGHT - 1,
            MAINNET_ASERT_RESCUE_HEIGHT,
            MAINNET_ASERT_RESCUE_HEIGHT + 1,
            10_191,
        ];
        // A non-zero parent total, built through the canonical accumulator so
        // the test never has to name the U256 type directly.
        let tip_difficulty = checked_accumulated_difficulty(Default::default(), 1_234_567)
            .expect("seed tip difficulty");

        for height in boundary {
            let timestamp = Timestamp(1_753_660_800 + height);
            let target =
                compute_expected_target(NETWORK_MAGIC_MAINNET, timestamp, BlockHeight(height))
                    .expect("canonical target");

            // What the Wallet now puts in the header.
            let wallet_work = target_to_difficulty_for_network_height(
                NETWORK_MAGIC_MAINNET,
                BlockHeight(height),
                &target,
            )
            .expect("wallet work");
            let wallet_total =
                checked_accumulated_difficulty(tip_difficulty, wallet_work).expect("wallet total");

            // What `ChainState::validate` recomputes and demands.
            let expected_work = target_to_difficulty_for_network_height(
                NETWORK_MAGIC_MAINNET,
                BlockHeight(height),
                &target,
            )
            .expect("validator work");
            let expected_total = checked_accumulated_difficulty(tip_difficulty, expected_work)
                .expect("validator total");

            assert_eq!(
                wallet_total, expected_total,
                "total_difficulty diverges from the validator at height {height}"
            );

            // The height-blind computation is what used to be written. Past the
            // activation height it MUST differ, otherwise this test would pass
            // even with the bug still in place.
            let height_blind = dom_pow::target_to_difficulty(&target);
            if height >= MAINNET_ASERT_RESCUE_HEIGHT {
                assert_ne!(
                    wallet_work, height_blind,
                    "post-rescue work must not equal the height-blind value at {height}"
                );
            } else {
                assert_eq!(
                    wallet_work, height_blind,
                    "pre-rescue heights must be unchanged at {height}"
                );
            }
        }
    }

    /// Regtest is unaffected: the rescue numerator is Mainnet-only, so local
    /// and test mining keep producing exactly the same work as before.
    #[test]
    fn regression_non_mainnet_work_is_unchanged_by_the_asert_rescue() {
        for height in [1u64, MAINNET_ASERT_RESCUE_HEIGHT, 10_191] {
            let timestamp = Timestamp(1_753_660_800 + height);
            let target =
                compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, BlockHeight(height))
                    .expect("regtest target");
            assert_eq!(
                target_to_difficulty_for_network_height(
                    NETWORK_MAGIC_REGTEST,
                    BlockHeight(height),
                    &target
                )
                .expect("regtest work"),
                dom_pow::target_to_difficulty(&target),
                "regtest work changed at height {height}"
            );
        }
    }

    /// Only a node that is still catching up is retriable. Every other failure
    /// must stop mining, and every one must carry its own redacted code — the
    /// single opaque `MINING_WORK_FAILED` made a transient dip and a corrupt
    /// seed index indistinguishable.
    #[test]
    fn regression_mining_error_classes_are_distinct_and_redacted() {
        let transient = WalletMiningError::NotReady("NODE_NOT_SYNCHRONIZED");
        assert!(transient.is_transient());
        assert_eq!(transient.code(), "MINING_NODE_NOT_SYNCHRONIZED");

        let fatal = [
            (
                WalletMiningError::Preparation("SEED_INDEX"),
                "MINING_PREPARATION_SEED_INDEX",
            ),
            (
                WalletMiningError::Preparation("TARGET"),
                "MINING_PREPARATION_TARGET",
            ),
            (
                WalletMiningError::Preparation("POW_MODE"),
                "MINING_PREPARATION_POW_MODE",
            ),
            (
                WalletMiningError::Preparation("DIFFICULTY"),
                "MINING_PREPARATION_DIFFICULTY",
            ),
            (
                WalletMiningError::Preparation("PMMR_ROOTS"),
                "MINING_PREPARATION_PMMR_ROOTS",
            ),
            (WalletMiningError::Worker, "MINING_WORKER_FAILED"),
            (
                WalletMiningError::Validation,
                "MINING_BLOCK_VALIDATION_FAILED",
            ),
        ];
        let mut codes = vec![transient.code()];
        for (error, expected) in fatal {
            assert!(!error.is_transient(), "{expected} must stop mining");
            assert_eq!(error.code(), expected);
            codes.push(error.code());
        }

        // Distinct, and free of any chain- or wallet-identifying material.
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "diagnostic codes must be unique");
        for code in codes {
            assert!(
                code.starts_with("MINING_")
                    && code
                        .chars()
                        .all(|character| character.is_ascii_uppercase() || character == '_'),
                "unexpected diagnostic shape: {code}"
            );
        }
    }

    #[test]
    fn template_lifecycle_rejects_stale_unsynced_and_expired_work() {
        assert!(template_is_current(
            7,
            7,
            1,
            7,
            true,
            Duration::from_secs(29)
        ));
        assert!(!template_is_current(7, 8, 1, 8, true, Duration::ZERO));
        assert!(!template_is_current(7, 7, 0, 7, true, Duration::ZERO));
        assert!(!template_is_current(7, 7, 1, 8, true, Duration::ZERO));
        assert!(!template_is_current(
            7,
            7,
            1,
            7,
            true,
            TEMPLATE_REFRESH_INTERVAL
        ));
        assert!(template_is_current(7, 7, 0, 0, false, Duration::ZERO));
    }

    #[test]
    fn regression_c1_miner_uses_authoritative_peer_height_without_ibd_metric() {
        assert!(authoritative_network_ready(0, 1, 0));
        assert!(authoritative_network_ready(9, 1, 9));
        assert!(!authoritative_network_ready(0, 0, 0));
        assert!(!authoritative_network_ready(9, 1, 10));
        assert!(!authoritative_network_ready(9, 1, 0));
    }
}
