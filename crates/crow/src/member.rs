//! Nest membership types and canonical signing payloads.
//!
//! Membership in a nest is recorded as signed events in the catalog event
//! log. Each `MemberAdded` event carries a granter's signature over a small
//! canonical payload — `member_grant_canonical_bytes` — that uniquely
//! identifies the (nest, granter, member, role, added_at) tuple. The same
//! payload is signed at two points:
//!
//! 1. **Founding:** when a device creates a nest, it self-grants by signing
//!    the payload with its own identity (`granter == member`). The outer
//!    catalog-event signature and the embedded `invite_signature` then
//!    match.
//! 2. **Invited member:** an existing Owner produces the canonical bytes,
//!    signs them, and embeds the signature in the [`Invite`] payload. When
//!    the recipient writes their own `MemberAdded` event, they copy that
//!    signature into `invite_signature`. A third device merging the event
//!    can re-derive the canonical bytes from the event's fields and verify
//!    the granter authorised the grant.
//!
//! Revocation merge logic is deferred to Phase 5 (the orchestration plan
//! treats CRDT conflict resolution as its own design pass). The
//! [`MemberRevoked`](super::catalog::CatalogOp::MemberRevoked) op variant
//! and the `revoked_at` field on [`MemberRecord`] are reserved here so the
//! wire format does not change later.

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;
use crate::nest::NestId;

/// Domain-separation tag for member-grant signatures. Bumping this value
/// invalidates every existing grant signature on disk, so do not change it
/// without a migration story.
const GRANT_DOMAIN_TAG: &[u8] = b"crow.member-grant.v1";

/// The role assigned to a member. Phase 3 ships a single variant; future
/// roles (`Reader`, `Writer`, `Storage`) will land when there is a real
/// capability difference between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NestRole {
    Owner,
}

impl NestRole {
    /// Single-byte wire encoding used inside [`member_grant_canonical_bytes`].
    fn tag(self) -> u8 {
        match self {
            NestRole::Owner => 1,
        }
    }
}

/// A current-state member entry derived from the catalog event log by
/// [`CatalogView::members`](super::catalog::CatalogView::members).
///
/// `revoked_at` is reserved data shape: it is populated by a
/// `MemberRevoked` op but Phase 3 does not yet treat a revoked member as
/// non-current (that requires CRDT merge semantics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    pub member: NodeId,
    pub granter: NodeId,
    pub role: NestRole,
    pub added_at: u64,
    pub revoked_at: Option<u64>,
}

/// Canonical bytes a granter signs to authorise a `MemberAdded` event.
///
/// Same payload is used at three points:
/// 1. The founding device produces it when self-granting.
/// 2. An Owner produces and signs it inside an `Invite` (Phase 3 commit 3).
/// 3. A verifier reconstructs it from a `MemberAdded` event's fields and
///    checks the embedded `invite_signature` against the named granter.
///
/// Encoding is a hand-rolled, fixed-layout byte string rather than postcard,
/// so the canonical form does not depend on a particular serde version's
/// framing. Layout: `tag || nest_id(16) || granter(32) || member(32) ||
/// role(1) || added_at(u64 LE)`.
pub fn member_grant_canonical_bytes(
    nest_id: &NestId,
    granter: &NodeId,
    member: &NodeId,
    role: NestRole,
    added_at: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(GRANT_DOMAIN_TAG.len() + 16 + 32 + 32 + 1 + 8);
    out.extend_from_slice(GRANT_DOMAIN_TAG);
    out.extend_from_slice(nest_id.as_bytes());
    out.extend_from_slice(granter.as_bytes());
    out.extend_from_slice(member.as_bytes());
    out.push(role.tag());
    out.extend_from_slice(&added_at.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_stable() {
        let nest = NestId::from_bytes([0x11u8; 16]);
        let granter = NodeId::from_bytes([0x22u8; 32]);
        let member = NodeId::from_bytes([0x33u8; 32]);
        let bytes = member_grant_canonical_bytes(&nest, &granter, &member, NestRole::Owner, 42);
        // Locked-in layout so accidental changes break the test, not the
        // wire format.
        assert_eq!(&bytes[..GRANT_DOMAIN_TAG.len()], GRANT_DOMAIN_TAG);
        assert_eq!(
            &bytes[GRANT_DOMAIN_TAG.len()..GRANT_DOMAIN_TAG.len() + 16],
            &[0x11u8; 16]
        );
        let role_offset = GRANT_DOMAIN_TAG.len() + 16 + 32 + 32;
        assert_eq!(bytes[role_offset], 1); // Owner = 1
        assert_eq!(
            &bytes[role_offset + 1..],
            &42u64.to_le_bytes(),
            "added_at tail is little-endian"
        );
    }

    #[test]
    fn canonical_bytes_differ_when_any_field_changes() {
        let n = NestId::from_bytes([0u8; 16]);
        let g = NodeId::from_bytes([0u8; 32]);
        let m = NodeId::from_bytes([1u8; 32]);
        let base = member_grant_canonical_bytes(&n, &g, &m, NestRole::Owner, 100);
        assert_ne!(
            base,
            member_grant_canonical_bytes(
                &NestId::from_bytes([1u8; 16]),
                &g,
                &m,
                NestRole::Owner,
                100,
            )
        );
        assert_ne!(
            base,
            member_grant_canonical_bytes(&n, &g, &m, NestRole::Owner, 101,)
        );
    }
}
