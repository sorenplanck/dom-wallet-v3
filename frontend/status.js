export function synchronizationPresentation(network, peers, synchronization) {
  const localHeight = Number.isSafeInteger(network?.canonical_height)
    ? network.canonical_height
    : 0;
  const reportedPeerHeight = Number.isSafeInteger(peers?.highest_known_peer_height)
    ? peers.highest_known_peer_height
    : localHeight;
  const peerHeight = Math.max(localHeight, reportedPeerHeight);
  const progress = peerHeight > 0
    ? Math.min(100, Math.floor((localHeight * 100) / peerHeight))
    : 0;

  if (peerHeight > localHeight) {
    return {
      badgeState: "SYNCHRONIZING",
      message: `Synchronizing ${localHeight} / ${peerHeight} (${progress}%)`,
      localHeight,
      peerHeight,
      progress,
    };
  }
  if (synchronization?.synchronized) {
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

export function miningPresentation(mining, node) {
  const lifecycle = node?.lifecycle ?? "NOT_READY";
  const nodeReady = lifecycle === "READY" && node?.ready === true;
  if (!nodeReady) {
    return {
      status: lifecycle === "SYNCHRONIZING" ? "SYNCHRONIZING" : "NODE NOT READY",
      canStart: false,
      warning: node?.status_message ?? "The node must be ready before mining can start.",
    };
  }
  return {
    status: mining.status,
    canStart: mining.enabled === true && mining.running !== true,
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
