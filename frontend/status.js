export function synchronizationPresentation(network, peers, synchronization) {
  const localHeight = Number.isSafeInteger(network?.canonical_height)
    ? network.canonical_height
    : 0;
  const peerHeight = Number.isSafeInteger(peers?.highest_known_peer_height)
    ? peers.highest_known_peer_height
    : null;
  const connectedPeers = Number.isSafeInteger(peers?.total_connected_peers)
    ? peers.total_connected_peers
    : 0;
  const lifecycle = network?.lifecycle;
  const progress = peerHeight != null && peerHeight > 0
    ? Math.min(100, Math.floor((localHeight * 100) / peerHeight))
    : 0;

  // A paused worker never advances the cursor, and nothing in the interface
  // read `paused`: the balance simply stopped updating with no explanation,
  // including through a whole restore. It outranks the node states below
  // because no node condition can make progress while it holds.
  if (synchronization?.paused === true) {
    return {
      badgeState: "PAUSED",
      message: `Synchronization is paused at local height ${localHeight}. Resume it to continue.`,
      localHeight,
      peerHeight,
      progress,
    };
  }

  if (lifecycle === "FAILED" || lifecycle === "STALE" || lifecycle === "STOPPED"
    || lifecycle === "STARTING") {
    return {
      badgeState: lifecycle,
      message: network?.status_message ?? `Node state: ${lifecycle}`,
      localHeight,
      peerHeight,
      progress,
    };
  }
  if (connectedPeers === 0 || lifecycle === "WAITING_FOR_PEERS") {
    return {
      badgeState: "WAITING_FOR_PEERS",
      message: `Waiting for peers at local height ${localHeight}`,
      localHeight,
      peerHeight: null,
      progress: 0,
    };
  }
  if (peerHeight == null || lifecycle === "UNKNOWN_PEER_HEIGHT") {
    return {
      badgeState: "UNKNOWN_PEER_HEIGHT",
      message: `Connected; waiting for authoritative peer height at ${localHeight}`,
      localHeight,
      peerHeight: null,
      progress: 0,
    };
  }
  if (peerHeight > localHeight || lifecycle === "SYNCHRONIZING") {
    return {
      badgeState: "SYNCHRONIZING",
      message: `Synchronizing ${localHeight} / ${peerHeight} (${progress}%)`,
      localHeight,
      peerHeight,
      progress,
    };
  }
  if (localHeight === 0 && peerHeight === 0) {
    return {
      badgeState: "CONNECTED_AT_GENESIS",
      message: "Connected to canonical peers at genesis",
      localHeight,
      peerHeight,
      progress: 100,
    };
  }
  if (peerHeight === localHeight && synchronization?.synchronized) {
    return {
      badgeState: "READY",
      message: `Wallet synchronized at height ${synchronization.cursor_height}`,
      localHeight,
      peerHeight,
      progress: 100,
    };
  }
  if (synchronization?.last_error) {
    return {
      badgeState: "ATTENTION",
      message: synchronization.last_error,
      localHeight,
      peerHeight,
      progress,
    };
  }
  return {
    badgeState: "PREPARING",
    message: "Preparing wallet synchronization",
    localHeight,
    peerHeight,
    progress,
  };
}

/// `submitEnabled` is `true` in every branch, and that is the product
/// decision, not an oversight: "Restore is always available. The wallet scans
/// the chain in the background while the node synchronizes" (index.html).
/// What this function gates is the *wording* - what the panel tells the user
/// about the node while the scan runs. Anyone tempted to make one of these
/// branches disable the button should read
/// `regression_restore_submit_is_enabled_in_every_node_state` first.
export function restoreReadinessPresentation(node) {
  const localHeight = Number.isSafeInteger(node?.canonical_tip_height)
    ? node.canonical_tip_height
    : 0;
  const peerHeight = Number.isSafeInteger(node?.highest_known_peer_height)
    ? node.highest_known_peer_height
    : 0;
  const connectedPeers = Number.isSafeInteger(node?.connected_peers)
    ? node.connected_peers
    : 0;
  const progress = peerHeight > 0
    ? Math.min(100, Math.floor((localHeight * 100) / peerHeight))
    : 0;
  const synchronized = node?.network === "MAINNET"
    && node?.lifecycle === "READY"
    && node?.ready === true
    && connectedPeers > 0
    && peerHeight > 0
    && localHeight >= peerHeight;

  if (synchronized) {
    return {
      submitEnabled: true,
      badge: "READY",
      message: `Mainnet node synchronized at height ${localHeight}.`,
      localHeight,
      peerHeight,
      connectedPeers,
      progress: 100,
    };
  }
  // A node that is stopped, failed or still starting has zero connected peers,
  // so it used to fall through to "Discovering Mainnet peers" - the panel
  // claimed progress at exactly the moment the node was not running at all
  // (closing a wallet stops it, for instance). Report what is actually
  // happening instead of inventing peer discovery.
  //
  // submitEnabled stays true: restore is always available and scans in the
  // background while the node comes up (see index.html and
  // regression_restore_submit_is_enabled_in_every_node_state). This branch
  // only corrects what the panel *says*, never what it allows.
  const lifecycle = node?.lifecycle;
  if (lifecycle === "STOPPED" || lifecycle === "FAILED" || lifecycle === "STARTING") {
    const message = lifecycle === "STARTING"
      ? "The Mainnet node is starting. Restore will scan as soon as it is up."
      : lifecycle === "STOPPED"
        ? "The Mainnet node is stopped. Restore will scan once it is running again."
        : node?.status_message
          ?? "The Mainnet node failed. Restore will scan once it recovers.";
    return {
      submitEnabled: true,
      badge: lifecycle,
      message,
      localHeight,
      peerHeight: null,
      connectedPeers,
      progress: 0,
    };
  }
  if (connectedPeers === 0) {
    return {
      submitEnabled: true,
      badge: "DISCOVERING",
      message: `Discovering Mainnet peers at local height ${localHeight}.`,
      localHeight,
      peerHeight: null,
      connectedPeers,
      progress: 0,
    };
  }
  if (peerHeight > localHeight) {
    return {
      submitEnabled: true,
      badge: "SYNCHRONIZING",
      message: `Synchronizing ${localHeight} / ${peerHeight} (${progress}%).`,
      localHeight,
      peerHeight,
      connectedPeers,
      progress,
    };
  }
  return {
    submitEnabled: true,
    badge: "FINALIZING",
    message: `Validating Mainnet state at height ${localHeight}.`,
    localHeight,
    peerHeight: peerHeight || null,
    connectedPeers,
    progress,
  };
}

/// The History used to print the backend's raw lifecycle identifier -
/// `RESPONSE_PREPARED`, `ACCEPTED_NOT_RELAYED` - straight at the user. Every
/// name `transaction_state_name` can produce is covered here; anything else
/// falls back to the identifier with its underscores softened, so a new
/// backend state degrades to something readable rather than to nothing.
const TRANSACTION_STATE_LABELS = {
  DRAFT: "Draft",
  INPUTS_RESERVED: "Inputs reserved",
  REQUEST_EXPORTED: "Request exported",
  REQUEST_IMPORTED: "Request imported",
  RESPONSE_PREPARED: "Response prepared",
  RESPONSE_EXPORTED: "Response exported",
  RESPONSE_IMPORTED: "Response imported",
  FINALIZED: "Finalized",
  SUBMITTING: "Submitting",
  SUBMITTED: "Submitted",
  ACCEPTED_NOT_RELAYED: "Accepted, not relayed",
  IN_MEMPOOL: "In mempool",
  CONFIRMED: "Confirmed",
  REORGED: "Reorganized out",
  RETRANSMIT_REQUIRED: "Retransmit required",
  CANCELLED: "Cancelled",
  FAILED: "Failed",
  RECONCILIATION_REQUIRED: "Reconciliation required",
};

export function transactionStateLabel(state) {
  if (typeof state !== "string" || state === "") return "Unknown";
  if (Object.hasOwn(TRANSACTION_STATE_LABELS, state)) return TRANSACTION_STATE_LABELS[state];
  const softened = state.replaceAll("_", " ").toLowerCase();
  return softened.charAt(0).toUpperCase() + softened.slice(1);
}

/// The balance is only the whole balance once the cursor has reached the tip.
/// `wallet_summary` returns `state.balance()` unconditionally, so a wallet
/// scanned to 30% of the chain presented 30% of its funds as an authoritative
/// figure, with nothing on the card to say so. This does not change the
/// numbers - it says what they are worth.
export function balanceCompletenessPresentation(synchronization) {
  if (synchronization?.synchronized === true) return { partial: false, message: null };
  const cursorHeight = Number.isSafeInteger(synchronization?.cursor_height)
    ? synchronization.cursor_height
    : null;
  const tipHeight = Number.isSafeInteger(synchronization?.tip_height)
    ? synchronization.tip_height
    : null;
  if (synchronization == null) {
    return {
      partial: true,
      message: "Partial balance: synchronization status is unavailable, so these figures may be incomplete.",
    };
  }
  if (cursorHeight != null && tipHeight != null && tipHeight > 0) {
    const progress = Math.min(100, Math.floor((cursorHeight * 100) / tipHeight));
    return {
      partial: true,
      message: `Partial balance: scanned to height ${cursorHeight} of ${tipHeight} (${progress}%). Funds above that height are not counted yet.`,
    };
  }
  return {
    partial: true,
    message: "Partial balance: the wallet is still synchronizing, so these figures are incomplete.",
  };
}

export function restoreScanPresentation(synchronization) {
  const active = synchronization?.seed_restore_in_progress === true;
  const cursorHeight = Number.isSafeInteger(synchronization?.cursor_height)
    ? synchronization.cursor_height
    : 0;
  const tipHeight = Number.isSafeInteger(synchronization?.tip_height)
    ? synchronization.tip_height
    : null;
  const reportedPercent = synchronization?.scan_progress_percent;
  const progress = Number.isSafeInteger(reportedPercent)
    ? Math.min(100, Math.max(0, reportedPercent))
    : tipHeight != null && tipHeight > 0
      ? Math.min(100, Math.floor((cursorHeight * 100) / tipHeight))
      : 0;
  // `partial_balance` is always a BalanceProjection object; the old scalar
  // branch was unreachable. Prefer `total`: reporting only `confirmed` hid
  // every immature coinbase, which for a mining wallet being restored is
  // essentially the whole balance, so the panel showed ~0 while the scan was
  // in fact finding money.
  const partial = synchronization?.partial_balance;
  const partialNoms = Number.isSafeInteger(partial?.total)
    ? partial.total
    : Number.isSafeInteger(partial?.confirmed)
      ? partial.confirmed
      : null;
  if (!active) {
    return {
      active: false,
      message: null,
      progress,
      cursorHeight,
      tipHeight,
      partialBalanceText: null,
    };
  }
  return {
    active: true,
    message: tipHeight != null
      ? `Restored — scanning block ${cursorHeight} of ${tipHeight} (${progress}%)`
      : `Restored — scanning block ${cursorHeight}`,
    progress,
    cursorHeight,
    tipHeight,
    partialBalanceText: partialNoms == null
      ? "Partial balance: unavailable"
      : `Partial balance: ${formatDomFromNoms(partialNoms)}`,
  };
}

export function remoteTipAlertPresentation(synchronization) {
  const active = synchronization?.remote_tip_alert === true;
  return {
    active,
    message: active
      ? "Remote node alert: the reported chain tip regressed or is inconsistent. Verify your remote node before trusting balances."
      : null,
  };
}

export function chainSourceTlsWarning(baseUrl) {
  if (typeof baseUrl !== "string" || baseUrl.trim() === "") return false;
  let parsed;
  try {
    parsed = new URL(baseUrl.trim());
  } catch {
    return true;
  }
  if (parsed.protocol === "https:") return false;
  const host = parsed.hostname.toLowerCase();
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  return !isLocal;
}

export function chainSourcePresentation(value) {
  const source = value?.source === "REMOTE" ? "REMOTE" : "EMBEDDED";
  const baseUrl = typeof value?.base_url === "string" && value.base_url !== ""
    ? value.base_url
    : null;
  const tlsWarning = value?.tls_warning === true
    || (source === "REMOTE" && chainSourceTlsWarning(baseUrl ?? ""));
  return {
    source,
    baseUrl,
    hasBearerToken: value?.has_bearer_token === true,
    tlsWarning,
    message: source === "REMOTE"
      ? `Remote node (fast): ${baseUrl ?? "no URL configured"}`
      : "Local full node (default): the embedded node validates the entire chain.",
  };
}

export function liveStatusProjection(summary, node, network, peers, synchronization) {
  const nodeHeight = Number.isSafeInteger(node?.canonical_tip_height)
    ? node.canonical_tip_height
    : undefined;
  const networkHeight = Number.isSafeInteger(network?.canonical_height)
    ? network.canonical_height
    : undefined;
  const canonicalHeight = nodeHeight ?? networkHeight;
  const connectedPeers = Number.isSafeInteger(node?.connected_peers)
    ? node.connected_peers
    : Number.isSafeInteger(peers?.total_connected_peers)
      ? peers.total_connected_peers
      : undefined;
  const highestPeerHeight = Number.isSafeInteger(node?.highest_known_peer_height)
    ? node.highest_known_peer_height
    : Number.isSafeInteger(peers?.highest_known_peer_height)
      ? peers.highest_known_peer_height
      : undefined;
  const cursorHeight = synchronization?.cursor_height ?? summary?.cursor_height ?? null;

  const effectiveNetwork = canonicalHeight == null
    ? undefined
    : {
        canonical_height: canonicalHeight,
        lifecycle: node?.lifecycle,
        status_message: node?.status_message,
      };
  const effectivePeers = canonicalHeight == null
    ? undefined
    : {
        highest_known_peer_height: highestPeerHeight,
        total_connected_peers: connectedPeers,
      };
  const effectiveSynchronization = canonicalHeight == null
    ? undefined
    : synchronization ?? {
        cursor_height: cursorHeight,
        synchronized: false,
        last_error: null,
      };
  const synchronizationState = effectiveNetwork && effectivePeers && effectiveSynchronization
    ? synchronizationPresentation(
        effectiveNetwork,
        effectivePeers,
        effectiveSynchronization,
      )
    : undefined;

  return {
    badgeState: synchronizationState?.badgeState
      ?? (canonicalHeight == null ? "NODE UNAVAILABLE" : "PREPARING"),
    message: synchronizationState?.message
      ?? (canonicalHeight == null
        ? "Waiting for the embedded node"
        : "Waiting for wallet synchronization status"),
    synchronizationState,
    canonicalHeight,
    cursorHeight,
    connectedPeers,
    highestPeerHeight,
    chainId: node?.chain_id ?? network?.chain_id,
    genesisHash: node?.genesis_hash ?? network?.genesis_hash,
    dataDirectory: network?.data_directory,
    bootstrapPhase: node?.bootstrap_phase ?? peers?.bootstrap_phase,
  };
}

export function miningPresentation(mining, node) {
  const lifecycle = node?.lifecycle ?? "NOT_READY";
  const nodeReady = (lifecycle === "READY" || lifecycle === "CONNECTED_AT_GENESIS")
    && node?.ready === true;
  if (!nodeReady) {
    return {
      status: lifecycle === "SYNCHRONIZING" ? "SYNCHRONIZING" : "NODE NOT READY",
      canStart: false,
      warning: node?.status_message ?? "The node must be ready before mining can start.",
    };
  }
  return {
    status: mining.status,
    // WAITING_FOR_SYNCHRONIZATION means the worker is alive and will resume on
    // its own, so Start must stay disabled — the backend rejects it as
    // MINING_RUNNING anyway, and offering it would look like mining is off.
    canStart: mining.enabled === true
      && mining.running !== true
      && mining.status !== "WAITING_FOR_SYNCHRONIZATION",
    warning: mining.current_height === 0
      ? "Starting mining may produce the first post-genesis Mainnet block."
      : null,
  };
}

export function nodeStatusText(value) {
  const localHeight = value.canonical_tip_height ?? "—";
  const peerHeight = value.highest_known_peer_height ?? "—";
  const progress = value.synchronization_progress_percent == null
    ? "—"
    : `${value.synchronization_progress_percent}%`;
  return [
    value.status_message,
    `Lifecycle: ${value.lifecycle}`,
    `Network: ${value.network ?? "—"}`,
    `Local height: ${localHeight}`,
    `Highest peer height: ${peerHeight}`,
    `Synchronization: ${progress}`,
    `Connected peers: ${value.connected_peers}`,
    `Bootstrap: ${value.bootstrap_phase}`,
    `Canonical hash: ${value.canonical_tip_hash ?? "—"}`,
    `Error: ${value.error_code ?? "None"}`,
  ].join("\n");
}

export function formatDomFromNoms(value) {
  if (!Number.isSafeInteger(value) || value < 0) return "Unavailable";
  const noms = BigInt(value);
  const unit = 100_000_000n;
  const whole = noms / unit;
  const fraction = String(noms % unit).padStart(8, "0");
  return `${whole}.${fraction} DOM`;
}

export function nomsFromDom(text) {
  const m = /^([0-9]+)(?:\.([0-9]{1,8}))?$/.exec(String(text).trim());
  if (!m) throw new Error("Enter an amount in DOM with at most 8 decimal places.");
  const noms = BigInt(m[1]) * 100000000n + BigInt((m[2] ?? "").padEnd(8, "0"));
  if (noms <= 0n) throw new Error("The amount must be greater than zero.");
  if (noms > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Amount exceeds the safe desktop boundary.");
  return Number(noms);
}

/// W8 — reachability presentation for the Node status screen.
///
/// Three distinct non-mesh states: user-chosen private mode
/// (preference off), a mesh listener that degraded to the loopback leaf
/// (preference on, listener not accepting), and the normal mesh states.
/// Any inbound peer proves reachability regardless of what the port
/// mapper reported (public IP, manual port-forward, hairpin).
export function reachabilityText(peers) {
  if (!peers) return ["\u2014", "\u2014"];
  if (!peers.accepting_inbound) {
    if (peers.inbound_preference_enabled) {
      return [
        "Could not open the network listener \u00b7 outbound connections only",
        "The preferred P2P ports were unavailable, so the wallet fell back to a private local listener. Synchronization continues normally; restart the node to try again.",
      ];
    }
    return ["Inbound connections disabled", "Private mode: this wallet only dials out, like v0.3.5."];
  }
  const reachablePort = peers.advertised_port || peers.p2p_listen_port;
  const detail = `Listening on port ${peers.p2p_listen_port} \u00b7 announced port ${peers.advertised_port || "\u2014"} \u00b7 inbound peers ${peers.connected_inbound}`;
  if (peers.connected_inbound > 0) {
    return [`Reachable from the network \u00b7 port ${reachablePort}`, detail];
  }
  if (peers.portmap_status === "upnp" || peers.portmap_status === "natpmp") {
    return ["Port open on the router \u00b7 waiting for connections", detail];
  }
  if (peers.portmap_status === "cgnat_detected") {
    return ["Your provider uses CGNAT \u00b7 outbound connections only", detail];
  }
  return ["Router did not open the port automatically", detail];
}
