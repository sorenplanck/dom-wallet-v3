//! Wallet-owned CPU miner adapter over the embedded canonical node.

use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    checked_accumulated_difficulty, compute_block_pmmr_roots, Block, CoinbaseTransaction,
};
use dom_core::{BlockHeight, Hash256, Timestamp};
use dom_node::node::DomNode;
use dom_pow::{
    compute_expected_target, fast_pow_hash, hash_meets_target, pow_validation_mode_for_network,
    randomx_pool, randomx_seed_height, target_to_compact, target_to_difficulty, CompactTarget,
    PowValidationMode,
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
    #[error("wallet mining preparation failed ({0})")]
    Preparation(&'static str),
    #[error("wallet mining worker failed")]
    Worker,
    #[error("wallet mined block validation failed")]
    Validation,
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
    let difficulty = target_to_difficulty(&target);
    let total_difficulty = checked_accumulated_difficulty(tip_difficulty, difficulty)
        .map_err(|_| WalletMiningError::Preparation("DIFFICULTY"))?;
    let transactions = Vec::new();
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(BlockHeight(height), coinbase, &transactions)
            .map_err(|_| WalletMiningError::Preparation("PMMR_ROOTS"))?;
    let template = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
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
                                .ibd_progress_percent
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
            && (node.metrics.peer_count.load(Ordering::Acquire) == 0
                || node.metrics.ibd_progress_percent.load(Ordering::Acquire) < 100)
        {
            Err(WalletMiningError::Preparation("NODE_NOT_SYNCHRONIZED"))
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
    ibd_progress_percent: u64,
    require_network_ready: bool,
    elapsed: Duration,
) -> bool {
    tip_height == current_height
        && elapsed < TEMPLATE_REFRESH_INTERVAL
        && (!require_network_ready || (peer_count > 0 && ibd_progress_percent >= 100))
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

    #[test]
    fn template_lifecycle_rejects_stale_unsynced_and_expired_work() {
        assert!(template_is_current(
            7,
            7,
            1,
            100,
            true,
            Duration::from_secs(29)
        ));
        assert!(!template_is_current(7, 8, 1, 100, true, Duration::ZERO));
        assert!(!template_is_current(7, 7, 0, 100, true, Duration::ZERO));
        assert!(!template_is_current(7, 7, 1, 99, true, Duration::ZERO));
        assert!(!template_is_current(
            7,
            7,
            1,
            100,
            true,
            TEMPLATE_REFRESH_INTERVAL
        ));
        assert!(template_is_current(7, 7, 0, 0, false, Duration::ZERO));
    }
}
