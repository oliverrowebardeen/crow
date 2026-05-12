//! Bech32m-encoded nest invites.
//!
//! An [`Invite`] is a portable, signed credential a nest Owner creates for a
//! specific recipient device. The recipient decodes it with
//! [`Invite::decode`], checks [`Invite::verify`] (signature + expiry), and on
//! `crow nest join` the granter's member-grant signature is embedded in the
//! resulting `MemberAdded` catalog event. Any third device that later merges
//! the membership event can re-derive the canonical grant bytes and re-verify
//! the granter authorised the addition.
//!
//! ## Wire shape
//!
//! - HRP: `crowinvite`
//! - Payload: postcard-serialised [`Invite`], then bech32m-encoded.
//! - `grant_signature` signs the recipient-specific member grant.
//! - `signature` signs the invite payload with `signature` zeroed during
//!   canonicalisation. Both encoder and verifier reconstruct the identical
//!   bytes deterministically.
//!
//! Invites are recipient-bound: the `member` field is the only device identity
//! that can redeem the invite. The encoded string is still sensitive in
//! transit, but a leaked invite cannot be used by a different device key.
//!
//! Bech32m's recommended QR-friendly length is 90 chars; Crow invites
//! often exceed that because they carry bootstrap addresses. We document
//! this rather than artificially truncate.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use bech32::{Bech32m, Hrp};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::manifest::Signature;
use crate::member::{NestRole, member_grant_canonical_bytes};
use crate::nest::NestId;

pub const INVITE_HRP: &str = "crowinvite";
pub const INVITE_VERSION: u8 = 1;

/// Maximum clock skew (in seconds) we tolerate between the granter and the
/// recipient when checking `expires_at`. Five minutes covers the realistic
/// drift between two consumer devices without keeping arbitrarily-old
/// invites alive.
pub const INVITE_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Soft limit on the number of bootstrap addresses an invite may carry.
/// Larger lists balloon the encoded length without helping the recipient
/// — `crow nest join` tries them in order with no concurrent racing.
pub const INVITE_MAX_BOOTSTRAP_ADDRS: usize = 4;

/// A signed nest invite. Created by `crow nest invite`; consumed by
/// `crow nest join`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    pub nest_id: NestId,
    /// Display-only nest name. Recipient should treat as untrusted text
    /// (length-capped at 32 chars when shown) and verify by `nest_id`.
    pub nest_name: String,
    /// Granter's Ed25519 identity. The catalog event log on the granter's
    /// device must already contain a `MemberAdded` for this NodeId.
    pub granter: NodeId,
    /// Recipient device identity this invite is bound to.
    pub member: NodeId,
    pub granted_role: NestRole,
    pub created_at: u64,
    /// Unix-seconds expiry. `0` means no expiry (use with caution).
    pub expires_at: u64,
    /// Up to [`INVITE_MAX_BOOTSTRAP_ADDRS`] socket addresses for the
    /// recipient to try in order when first syncing.
    pub bootstrap_addresses: Vec<SocketAddr>,
    /// Ed25519 signature by `granter` over
    /// [`member_grant_canonical_bytes`] for
    /// `(nest_id, granter, member, granted_role, created_at)`.
    pub grant_signature: Signature,
    /// Ed25519 signature by `granter` over [`Invite::canonical_bytes`].
    pub signature: Signature,
}

impl Invite {
    /// Build an unsigned invite. Call [`Invite::sign`] before encoding.
    pub fn new_unsigned(
        nest_id: NestId,
        nest_name: String,
        granter: NodeId,
        member: NodeId,
        granted_role: NestRole,
        expires_at: u64,
        bootstrap_addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            version: INVITE_VERSION,
            nest_id,
            nest_name,
            granter,
            member,
            granted_role,
            created_at: unix_now(),
            expires_at,
            bootstrap_addresses,
            grant_signature: Signature([0u8; 64]),
            signature: Signature([0u8; 64]),
        }
    }

    /// Sign with `identity`. Identity's pubkey must equal `self.granter`,
    /// otherwise the resulting signature won't verify.
    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        if identity.node_id() != self.granter {
            return Err(Error::Invite(
                "signing identity does not match Invite.granter".into(),
            ));
        }
        self.grant_signature = self.sign_member_grant(identity, &self.member, self.created_at)?;
        self.signature = Signature([0u8; 64]);
        let payload = self.canonical_bytes()?;
        let sig: Ed25519Signature = identity.signing.sign(&payload);
        self.signature = Signature(sig.to_bytes());
        Ok(())
    }

    /// Verify the signature and check that the invite has not expired.
    /// Returns the granter's NodeId on success. Use [`Invite::verify_at`]
    /// if you need to control the clock (e.g. in tests).
    pub fn verify(&self) -> Result<NodeId> {
        self.verify_at(unix_now())
    }

    /// Verify with a caller-supplied "now" in unix-seconds — used by tests
    /// to exercise expiry handling deterministically.
    pub fn verify_at(&self, now: u64) -> Result<NodeId> {
        if self.version != INVITE_VERSION {
            return Err(Error::Invite(format!(
                "unsupported invite version {}; this build supports {INVITE_VERSION}",
                self.version
            )));
        }
        if self.bootstrap_addresses.len() > INVITE_MAX_BOOTSTRAP_ADDRS {
            return Err(Error::Invite(format!(
                "invite carries {} bootstrap addresses; max {INVITE_MAX_BOOTSTRAP_ADDRS}",
                self.bootstrap_addresses.len()
            )));
        }
        let mut canonical = self.clone();
        canonical.signature = Signature([0u8; 64]);
        let payload = canonical.canonical_bytes()?;
        let granter_key = VerifyingKey::from_bytes(self.granter.as_bytes())
            .map_err(|e| Error::Invite(format!("invalid granter pubkey: {e}")))?;
        let sig = Ed25519Signature::from_bytes(&self.signature.0);
        granter_key
            .verify(&payload, &sig)
            .map_err(|_| Error::Invite("invalid signature".into()))?;
        self.verify_member_grant()?;
        if self.expires_at != 0 && now > self.expires_at + INVITE_CLOCK_SKEW_SECS {
            return Err(Error::Invite(format!(
                "invite expired {} seconds ago",
                now.saturating_sub(self.expires_at)
            )));
        }
        Ok(self.granter)
    }

    /// Verify that `grant_signature` authorises exactly this invite's
    /// recipient membership event.
    pub fn verify_member_grant(&self) -> Result<()> {
        let payload = member_grant_canonical_bytes(
            &self.nest_id,
            &self.granter,
            &self.member,
            self.granted_role,
            self.created_at,
        );
        let granter_key = VerifyingKey::from_bytes(self.granter.as_bytes())
            .map_err(|e| Error::Invite(format!("invalid granter pubkey: {e}")))?;
        let sig = Ed25519Signature::from_bytes(&self.grant_signature.0);
        granter_key
            .verify(&payload, &sig)
            .map_err(|_| Error::Invite("invalid member grant signature".into()))
    }

    /// Produce the granter's `MemberAdded.invite_signature` value: the
    /// granter signs [`member_grant_canonical_bytes`] for the recipient's
    /// pubkey. This is what the recipient embeds in their `MemberAdded`
    /// catalog event when joining; subsequent merges of that event by a
    /// third device verify the chain of trust without seeing the original
    /// Invite bytes.
    pub fn sign_member_grant(
        &self,
        identity: &Identity,
        member: &NodeId,
        added_at: u64,
    ) -> Result<Signature> {
        if identity.node_id() != self.granter {
            return Err(Error::Invite(
                "signing identity does not match Invite.granter".into(),
            ));
        }
        let payload = member_grant_canonical_bytes(
            &self.nest_id,
            &self.granter,
            member,
            self.granted_role,
            added_at,
        );
        let sig: Ed25519Signature = identity.signing.sign(&payload);
        Ok(Signature(sig.to_bytes()))
    }

    /// Encode as a `crowinvite1...` bech32m string. The wire bytes are the
    /// postcard encoding of `self` (signature included); the signed bytes
    /// are the same encoding with the signature field zeroed.
    pub fn encode(&self) -> Result<String> {
        let hrp = Hrp::parse(INVITE_HRP).expect("static HRP is valid");
        let wire =
            postcard::to_allocvec(self).map_err(|e| Error::Invite(format!("encode: {e}")))?;
        bech32::encode::<Bech32m>(hrp, &wire).map_err(|e| Error::Invite(format!("bech32m: {e}")))
    }

    /// Decode from a `crowinvite1...` string. Does **not** verify the
    /// signature or expiry — callers must invoke [`Invite::verify`].
    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s).map_err(|e| Error::Invite(format!("bech32m: {e}")))?;
        if hrp.as_str() != INVITE_HRP {
            return Err(Error::Invite(format!(
                "wrong HRP: expected {INVITE_HRP}, got {}",
                hrp.as_str()
            )));
        }
        let invite: Invite =
            postcard::from_bytes(&data).map_err(|e| Error::Invite(format!("decode: {e}")))?;
        if invite.version != INVITE_VERSION {
            return Err(Error::Invite(format!(
                "unsupported invite version {}; this build supports {INVITE_VERSION}",
                invite.version
            )));
        }
        Ok(invite)
    }

    /// Canonical bytes the granter signs. Same as the wire payload with
    /// `signature` zeroed; encoder and verifier reconstruct identically.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.signature = Signature([0u8; 64]);
        postcard::to_allocvec(&canonical).map_err(|e| Error::Invite(format!("encode: {e}")))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite_for(identity: &Identity, expires_at: u64) -> Invite {
        let mut invite = Invite::new_unsigned(
            NestId::from_bytes([0x11u8; 16]),
            "team".into(),
            identity.node_id(),
            NodeId::from_bytes([0xAAu8; 32]),
            NestRole::Owner,
            expires_at,
            vec!["127.0.0.1:7070".parse().unwrap()],
        );
        invite.sign(identity).unwrap();
        invite
    }

    #[test]
    fn encode_decode_roundtrip() {
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);
        let encoded = invite.encode().unwrap();
        assert!(encoded.starts_with("crowinvite1"));

        let decoded = Invite::decode(&encoded).unwrap();
        assert_eq!(decoded, invite);
        assert_eq!(decoded.verify().unwrap(), identity.node_id());
        decoded.verify_member_grant().unwrap();
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        // Take a known invite, re-encode with the wrong HRP, and confirm
        // decode rejects it.
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);
        let wire = postcard::to_allocvec(&invite).unwrap();
        let bad = bech32::encode::<Bech32m>(Hrp::parse("wronghrp").unwrap(), &wire).unwrap();
        let err = Invite::decode(&bad).unwrap_err();
        assert!(matches!(err, Error::Invite(msg) if msg.contains("wrong HRP")));
    }

    #[test]
    fn decode_rejects_tampered_payload() {
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);

        // Tamper the postcard payload by changing nest_name without
        // re-signing, then re-bech32m-encode it. Decoding succeeds (the
        // wire format is fine) but `verify` must reject the mismatched
        // signature.
        let mut bad = invite.clone();
        bad.nest_name = "evil".into();
        let wire = postcard::to_allocvec(&bad).unwrap();
        let bad_encoded =
            bech32::encode::<Bech32m>(Hrp::parse(INVITE_HRP).unwrap(), &wire).unwrap();

        let parsed = Invite::decode(&bad_encoded).unwrap();
        let err = parsed.verify().unwrap_err();
        assert!(matches!(err, Error::Invite(msg) if msg.contains("invalid signature")));
    }

    #[test]
    fn decode_rejects_tampered_member_grant() {
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);

        let mut bad = invite.clone();
        bad.member = NodeId::from_bytes([0xBBu8; 32]);
        let wire = postcard::to_allocvec(&bad).unwrap();
        let bad_encoded =
            bech32::encode::<Bech32m>(Hrp::parse(INVITE_HRP).unwrap(), &wire).unwrap();

        let parsed = Invite::decode(&bad_encoded).unwrap();
        let err = parsed.verify().unwrap_err();
        assert!(matches!(err, Error::Invite(msg) if msg.contains("invalid signature")));
    }

    #[test]
    fn decode_rejects_invalid_bech32_checksum() {
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);
        let encoded = invite.encode().unwrap();
        // Flip the last (checksum) character.
        let mut chars: Vec<char> = encoded.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(Invite::decode(&tampered).is_err());
    }

    #[test]
    fn expiry_in_past_rejected() {
        let identity = Identity::random();
        let expires_at = 1_000_000_000u64;
        let invite = invite_for(&identity, expires_at);
        // "now" is well past expiry + clock skew.
        let now = expires_at + INVITE_CLOCK_SKEW_SECS + 1;
        let err = invite.verify_at(now).unwrap_err();
        assert!(matches!(err, Error::Invite(msg) if msg.contains("expired")));
    }

    #[test]
    fn expiry_within_clock_skew_accepted() {
        let identity = Identity::random();
        let expires_at = 1_000_000_000u64;
        let invite = invite_for(&identity, expires_at);
        // Just barely past expiry, inside the clock-skew window.
        assert_eq!(
            invite.verify_at(expires_at + 1).unwrap(),
            identity.node_id()
        );
        assert_eq!(
            invite
                .verify_at(expires_at + INVITE_CLOCK_SKEW_SECS)
                .unwrap(),
            identity.node_id()
        );
    }

    #[test]
    fn expiry_zero_means_no_expiry() {
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);
        // Verify at an absurdly large "now" — should still succeed.
        assert!(invite.verify_at(u64::MAX / 2).is_ok());
    }

    #[test]
    fn sign_rejects_wrong_identity() {
        let owner = Identity::random();
        let other = Identity::random();
        let mut invite = Invite::new_unsigned(
            NestId::from_bytes([0u8; 16]),
            "n".into(),
            owner.node_id(),
            NodeId::from_bytes([0xABu8; 32]),
            NestRole::Owner,
            0,
            vec![],
        );
        let err = invite.sign(&other).unwrap_err();
        assert!(matches!(err, Error::Invite(msg) if msg.contains("does not match")));
    }

    #[test]
    fn sign_member_grant_matches_canonical_payload() {
        // Sanity check that Invite::sign_member_grant produces a signature
        // verifiable by member_grant_canonical_bytes. This is the bridge
        // to MemberAdded.invite_signature used in commit 4.
        let identity = Identity::random();
        let invite = invite_for(&identity, 0);
        let member = NodeId::from_bytes([0xAAu8; 32]);
        let added_at = 1_234_567_u64;
        let sig = invite
            .sign_member_grant(&identity, &member, added_at)
            .unwrap();

        let payload = member_grant_canonical_bytes(
            &invite.nest_id,
            &invite.granter,
            &member,
            invite.granted_role,
            added_at,
        );
        let key = VerifyingKey::from_bytes(invite.granter.as_bytes()).unwrap();
        assert!(
            key.verify(&payload, &Ed25519Signature::from_bytes(&sig.0))
                .is_ok()
        );
    }
}
