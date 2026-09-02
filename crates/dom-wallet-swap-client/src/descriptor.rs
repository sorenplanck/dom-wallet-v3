//! The operator-supplied swap network descriptor.
//!
//! Chain and asset identifiers of the interop network are 32-byte
//! registry ids derived from reviewed chain profiles — safety-critical
//! configuration, never tickers (dom-protocol `chain-profile`). The
//! wallet therefore never invents them: the operator hands the wallet
//! one descriptor naming the network, the DOM chain id, the curated
//! asset registry, the roster snapshot and the participants. Without a
//! valid descriptor the client cannot exist and nothing is ever sent —
//! the same fail-closed posture the swap tab has today.

use relay::auth::{RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::{ParticipantId, SenderRoleV1};
use rfq::{AssetId, ChainId, PolicyId};
use serde::Deserialize;

use crate::SwapClientError;

/// 32-byte digest, the id currency of the interop layer.
pub type Digest32 = [u8; 32];

/// Frozen descriptor format version.
pub const DESCRIPTOR_VERSION: u32 = 1;
/// Bound on roster members and assets: descriptors are reviewed by a
/// person, so they stay small (I14: bound first).
pub const MAX_DESCRIPTOR_ENTRIES: usize = 64;

/// One curated asset: the wallet-facing code and its registry identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetEntryV1 {
    /// Wallet-facing code (`"DOM"`, `"BTC"`, `"USDT"`, `"XMR"`, `"SOL"`).
    pub code: String,
    /// 32-byte chain registry id of the leg.
    pub chain_id: ChainId,
    /// 32-byte asset registry id.
    pub asset_id: AssetId,
}

/// The validated descriptor.
#[derive(Clone, Debug)]
pub struct SwapNetworkDescriptorV1 {
    /// Interop network id every envelope carries.
    pub network_id: Digest32,
    /// The DOM chain's registry id (AD-1.1 centrality checks).
    pub dom_chain_id: ChainId,
    /// The F4 assurance policy the RFQs reference.
    pub assurance_policy_ref: PolicyId,
    /// Policy version the session accepts.
    pub policy_version: u32,
    /// Roster snapshot id envelopes are signed under.
    pub roster_snapshot: Digest32,
    /// This wallet's participant id (role Initiator in the roster).
    pub user: ParticipantId,
    /// Solvers to fan the RFQ out to (each role Solver in the roster).
    pub solvers: Vec<ParticipantId>,
    members: Vec<(ParticipantId, RosterMemberV1)>,
    assets: Vec<AssetEntryV1>,
}

#[derive(Deserialize)]
struct RawDescriptor {
    version: u32,
    network_id: String,
    dom_chain_id: String,
    assurance_policy_ref: String,
    policy_version: u32,
    roster_snapshot: String,
    user_participant_id: String,
    members: Vec<RawMember>,
    solvers: Vec<String>,
    assets: Vec<RawAsset>,
}

#[derive(Deserialize)]
struct RawMember {
    participant_id: String,
    xonly_key: String,
    role: String,
}

#[derive(Deserialize)]
struct RawAsset {
    code: String,
    chain_id: String,
    asset_id: String,
}

fn hex32(text: &str) -> Result<Digest32, SwapClientError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| SwapClientError::DescriptorInvalid)?;
    Ok(out)
}

fn role_of(text: &str) -> Result<SenderRoleV1, SwapClientError> {
    match text {
        "initiator" => Ok(SenderRoleV1::Initiator),
        "solver" => Ok(SenderRoleV1::Solver),
        "observer" => Ok(SenderRoleV1::Observer),
        _ => Err(SwapClientError::DescriptorInvalid),
    }
}

impl SwapNetworkDescriptorV1 {
    /// Parses and validates one descriptor. Every refusal is
    /// fail-closed: a descriptor that does not validate does not exist.
    pub fn from_json(text: &str) -> Result<Self, SwapClientError> {
        let raw: RawDescriptor =
            serde_json::from_str(text).map_err(|_| SwapClientError::DescriptorInvalid)?;
        if raw.version != DESCRIPTOR_VERSION {
            return Err(SwapClientError::DescriptorInvalid);
        }
        if raw.members.is_empty()
            || raw.members.len() > MAX_DESCRIPTOR_ENTRIES
            || raw.solvers.is_empty()
            || raw.solvers.len() > MAX_DESCRIPTOR_ENTRIES
            || raw.assets.len() < 2
            || raw.assets.len() > MAX_DESCRIPTOR_ENTRIES
        {
            return Err(SwapClientError::DescriptorInvalid);
        }

        let user = ParticipantId(hex32(&raw.user_participant_id)?);
        let mut members = Vec::with_capacity(raw.members.len());
        for member in &raw.members {
            let id = ParticipantId(hex32(&member.participant_id)?);
            if members.iter().any(|(existing, _)| *existing == id) {
                return Err(SwapClientError::DescriptorInvalid);
            }
            members.push((
                id,
                RosterMemberV1 {
                    xonly_key: hex32(&member.xonly_key)?,
                    role: role_of(&member.role)?,
                },
            ));
        }
        let member_role = |id: &ParticipantId| {
            members
                .iter()
                .find(|(existing, _)| existing == id)
                .map(|(_, member)| member.role)
        };
        if member_role(&user) != Some(SenderRoleV1::Initiator) {
            return Err(SwapClientError::DescriptorInvalid);
        }

        let mut solvers = Vec::with_capacity(raw.solvers.len());
        for solver in &raw.solvers {
            let id = ParticipantId(hex32(solver)?);
            if solvers.contains(&id) || member_role(&id) != Some(SenderRoleV1::Solver) {
                return Err(SwapClientError::DescriptorInvalid);
            }
            solvers.push(id);
        }

        let dom_chain_id = ChainId(hex32(&raw.dom_chain_id)?);
        let mut assets = Vec::with_capacity(raw.assets.len());
        for asset in &raw.assets {
            if asset.code.is_empty()
                || asset.code.len() > 8
                || !asset
                    .code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                || assets
                    .iter()
                    .any(|existing: &AssetEntryV1| existing.code == asset.code)
            {
                return Err(SwapClientError::DescriptorInvalid);
            }
            assets.push(AssetEntryV1 {
                code: asset.code.clone(),
                chain_id: ChainId(hex32(&asset.chain_id)?),
                asset_id: AssetId(hex32(&asset.asset_id)?),
            });
        }
        // The DOM itself must be a curated asset on the DOM chain: every
        // v1 route touches the DOM on exactly one leg (AD-1.1).
        if !assets
            .iter()
            .any(|asset| asset.code == "DOM" && asset.chain_id == dom_chain_id)
        {
            return Err(SwapClientError::DescriptorInvalid);
        }

        Ok(Self {
            network_id: hex32(&raw.network_id)?,
            dom_chain_id,
            assurance_policy_ref: PolicyId(hex32(&raw.assurance_policy_ref)?),
            policy_version: raw.policy_version,
            roster_snapshot: hex32(&raw.roster_snapshot)?,
            user,
            solvers,
            members,
            assets,
        })
    }

    /// The roster registry envelopes verify against.
    pub fn rosters(&self) -> RosterRegistryV1 {
        let mut snapshot = RosterSnapshotV1::new();
        for (id, member) in &self.members {
            snapshot = snapshot.with_member(*id, *member);
        }
        RosterRegistryV1::new().with_snapshot(self.roster_snapshot, snapshot)
    }

    /// The curated asset for a wallet code, if the operator listed it.
    pub fn asset(&self, code: &str) -> Option<&AssetEntryV1> {
        self.assets.iter().find(|asset| asset.code == code)
    }

    /// The full curated asset registry.
    pub fn assets(&self) -> &[AssetEntryV1] {
        &self.assets
    }

    /// The roster's x-only key for one participant.
    pub fn member_xonly(&self, id: &ParticipantId) -> Option<[u8; 32]> {
        self.members
            .iter()
            .find(|(existing, _)| existing == id)
            .map(|(_, member)| member.xonly_key)
    }
}
