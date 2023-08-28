use anyhow::{Context, Result};
use frost_core::frost::round2::compute_signature_share;
use frost_core::frost::{
    compute_binding_factor_list, compute_group_commitment, derive_interpolating_value,
};
use frost_core::Challenge;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::round1::SigningNonces;
use frost_secp256k1::round2::SignatureShare;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint};
use sha3::Digest;
use std::collections::HashMap;

pub type Scalar = frost_core::Scalar<frost_secp256k1::Secp256K1Sha256>;
pub type ScalarSerialization = frost_core::ScalarSerialization<frost_secp256k1::Secp256K1Sha256>;

pub use frost_secp256k1;
pub use frost_secp256k1::round1;
pub use frost_secp256k1::{Error, Identifier, SigningKey, SigningPackage};
pub use k256::elliptic_curve;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub e: Scalar,
    pub z: Scalar,
}

impl Signature {
    pub fn new(e: Scalar, z: Scalar) -> Self {
        Self { e, z }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.e.to_bytes());
        bytes[32..].copy_from_slice(&self.z.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self> {
        let e: &k256::FieldBytes = bytes[..32].try_into()?;
        let e = Option::from(Scalar::from_repr(*e)).context("malformed scalar")?;
        let z: &k256::FieldBytes = bytes[32..].try_into()?;
        let z = Option::from(Scalar::from_repr(*z)).context("malformed scalar")?;
        Ok(Self { e, z })
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        let signature =
            Self::from_bytes(array).map_err(|err| serde::de::Error::custom(format!("{err}")))?;
        Ok(signature)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey {
    inner: frost_secp256k1::VerifyingKey,
}

impl std::ops::Deref for VerifyingKey {
    type Target = frost_secp256k1::VerifyingKey;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl VerifyingKey {
    pub fn new(inner: frost_secp256k1::VerifyingKey) -> Self {
        Self { inner }
    }

    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self> {
        Ok(Self::new(frost_secp256k1::VerifyingKey::deserialize(
            bytes,
        )?))
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.inner.serialize()
    }

    fn to_affine(&self) -> AffinePoint {
        self.inner.to_element().to_affine()
    }

    pub fn to_px_parity(&self) -> ([u8; 32], u8) {
        let affine = self.to_affine();
        (affine.x().into(), affine.y_is_odd().unwrap_u8() + 27)
    }

    pub fn message_hash(&self, message: &[u8]) -> [u8; 32] {
        sha3::Keccak256::digest(message).into()
    }

    fn hashed_challenge(&self, message_hash: [u8; 32], r: ProjectivePoint) -> Scalar {
        let uncompressed = r.to_affine().to_encoded_point(false);
        let digest = sha3::Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let address_r: [u8; 20] = digest[12..].try_into().unwrap();

        let (pubkey_x, pubkey_y_parity) = self.to_px_parity();
        let mut e_hasher = sha3::Keccak256::new();
        e_hasher.update(address_r);
        e_hasher.update([pubkey_y_parity]);
        e_hasher.update(pubkey_x);
        e_hasher.update(message_hash);
        Scalar::from_repr(e_hasher.finalize()).unwrap()
    }

    fn challenge(&self, message: &[u8], r: ProjectivePoint) -> Scalar {
        self.hashed_challenge(self.message_hash(message), r)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let r = AffinePoint::GENERATOR * signature.z - self.inner.to_element() * signature.e;
        let ep = self.challenge(message, r);
        if signature.e != ep {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// FROST(secp256k1, SHA-256) keys, key generation, key shares.
pub mod keys {
    pub use frost_secp256k1::keys::*;
}

pub mod round2 {
    use super::*;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Implements [`sign`] from the spec.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    ///
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &SigningNonces,
        key_package: &KeyPackage,
    ) -> Result<SignatureShare, Error> {
        // Validate the signer's commitment is present in the signing package
        let commitment = signing_package
            .signing_commitments()
            .get(key_package.identifier())
            .ok_or(Error::MissingCommitment)?;

        // Validate if the signer's commitment exists
        if commitment != &signer_nonces.into() {
            return Err(Error::IncorrectCommitment);
        }

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list =
            compute_binding_factor_list(signing_package, key_package.group_public(), &[]);
        let binding_factor = binding_factor_list
            .get(key_package.identifier())
            .ok_or(Error::UnknownIdentifier)?
            .clone();

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

        // Compute Lagrange coefficient.
        let lambda_i = derive_interpolating_value(key_package.identifier(), signing_package)?;

        // Compute the per-message challenge.
        // NOTE: here we diverge from frost by using a different challenge format.
        let challenge =
            Challenge::from_scalar(VerifyingKey::new(*key_package.group_public()).challenge(
                signing_package.message().as_slice(),
                group_commitment.to_element(),
            ));

        // Compute the Schnorr signature share.
        let signature_share = compute_signature_share(
            signer_nonces,
            binding_factor,
            lambda_i,
            key_package,
            challenge,
        );

        Ok(signature_share)
    }

    pub use frost_secp256k1::round2::SignatureShare;
}

////////////////////////////////////////////////////////////////////////////////
// Aggregation
////////////////////////////////////////////////////////////////////////////////

/// Aggregates the signature shares to produce a final signature that
/// can be verified with the group public key.
///
/// `signature_shares` maps the identifier of each participant to the
/// [`round2::SignatureShare`] they sent. These identifiers must come from whatever mapping
/// the coordinator has between communication channels and participants, i.e.
/// they must have assurance that the [`round2::SignatureShare`] came from
/// the participant with that identifier.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &HashMap<Identifier, SignatureShare>,
    pubkeys: &PublicKeyPackage,
) -> Result<Signature, Error> {
    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list =
        compute_binding_factor_list(signing_package, pubkeys.group_public(), &[]);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-5.3
    let mut z = Scalar::ZERO;

    for signature_share in signature_shares.values() {
        z += signature_share.share();
    }

    let challenge = VerifyingKey::new(*pubkeys.group_public()).challenge(
        signing_package.message().as_slice(),
        group_commitment.to_element(),
    );

    let signature = Signature::new(challenge, z);

    // Verify the aggregate signature
    let verification_result =
        VerifyingKey::new(*pubkeys.group_public()).verify(signing_package.message(), &signature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if let Err(err) = verification_result {
        // Verify the signature shares.
        for (signature_share_identifier, signature_share) in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .signer_pubkeys()
                .get(signature_share_identifier)
                .unwrap();

            // Compute Lagrange coefficient.
            let lambda_i = derive_interpolating_value(signature_share_identifier, signing_package)?;

            let binding_factor = binding_factor_list
                .get(signature_share_identifier)
                .ok_or(Error::UnknownIdentifier)?
                .clone();

            // Compute the commitment share.
            let r_share = signing_package
                .signing_commitment(signature_share_identifier)
                .ok_or(Error::UnknownIdentifier)?
                .to_group_commitment_share(&binding_factor);

            // Compute relation values to verify this signature share.
            signature_share.verify(
                *signature_share_identifier,
                &r_share,
                signer_pubkey,
                lambda_i,
                &Challenge::from_scalar(challenge),
            )?;
        }

        // We should never reach here; but we return the verification error to be safe.
        return Err(err);
    }

    Ok(signature)
}
