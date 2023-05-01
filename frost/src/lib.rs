use crypto_bigint::ArrayEncoding;
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
use k256::elliptic_curve::{Curve, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::Digest;

pub use frost_secp256k1::round1;
pub use frost_secp256k1::{Error, Identifier, SigningKey, SigningPackage};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub address: [u8; 20],
    pub z: Scalar,
}

impl Signature {
    pub fn new(r: ProjectivePoint, z: Scalar) -> Self {
        let address = to_address(r);
        Self { address, z }
    }
}

fn challenge(address: [u8; 20], verifying_key: &ProjectivePoint, msg: &[u8]) -> Scalar {
    let message_hash = sha3::Keccak256::digest(msg);
    let public_key = verifying_key.to_affine();
    let pubkey_x: [u8; 32] = public_key.x().into();
    let pubkey_y_parity = public_key.y_is_odd().unwrap_u8();
    let mut e_hasher = sha3::Keccak256::new();
    e_hasher.update(pubkey_x);
    e_hasher.update([pubkey_y_parity]);
    e_hasher.update(message_hash);
    e_hasher.update(address);
    Scalar::from_repr(e_hasher.finalize()).unwrap()
}

fn to_address(pubkey: ProjectivePoint) -> [u8; 20] {
    let uncompressed = pubkey.to_affine().to_encoded_point(false);
    let digest = sha3::Keccak256::digest(&uncompressed.as_bytes()[1..]);
    digest[12..].try_into().unwrap()
}

pub struct VerifyingKey {
    inner: frost_secp256k1::VerifyingKey,
}

impl std::ops::Deref for VerifyingKey {
    type Target = frost_secp256k1::VerifyingKey;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

const Q: k256::U256 = <k256::Secp256k1 as Curve>::ORDER;
const HALF_Q: k256::U256 = Q.shr_vartime(1).saturating_add(&k256::U256::ONE);

impl VerifyingKey {
    pub fn new(inner: frost_secp256k1::VerifyingKey) -> Result<Self, Error> {
        let pubkey = inner.to_element().to_affine();
        if pubkey.x() >= HALF_Q.to_be_byte_array() {
            return Err(Error::MalformedVerifyingKey);
        }
        Ok(Self { inner })
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        const Q: k256::U256 = <k256::Secp256k1 as Curve>::ORDER;
        const HALF_Q: k256::U256 = Q.shr_vartime(1).saturating_add(&k256::U256::ONE);
        let pubkey = self.to_element().to_affine();
        if pubkey.x() >= HALF_Q.to_be_byte_array() {
            return Err(Error::MalformedVerifyingKey);
        }
        if k256::U256::from(&signature.z) >= Q {
            return Err(Error::InvalidSignature);
        }
        let e = challenge(signature.address, &self.to_element(), msg);
        let n_times_g = AffinePoint::GENERATOR * signature.z + pubkey * e;
        let address = to_address(n_times_g);
        if address != signature.address {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// FROST(secp256k1, SHA-256) keys, key generation, key shares.
pub mod keys {
    use super::*;
    use std::collections::HashMap;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        mut rng: RNG,
    ) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        loop {
            let (shares, pubkey) =
                frost_core::frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)?;
            if VerifyingKey::new(pubkey.group_public).is_err() {
                continue;
            }
            return Ok((shares, pubkey));
        }
    }

    pub use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage, SecretShare};

    pub mod dkg {
        use super::*;
        pub use frost_secp256k1::keys::dkg::{part1, part2, round1, round2};

        /// Performs the third and final part of the distributed key generation protocol
        /// for the participant holding the given [`round2::SecretPackage`],
        /// given the received [`round1::Package`]s and [`round2::Package`]s received from
        /// the other participants.
        ///
        /// It returns the [`KeyPackage`] that has the long-lived key share for the
        /// participant, and the [`PublicKeyPackage`]s that has public information
        /// about all participants; both of which are required to compute FROST
        /// signatures.
        pub fn part3(
            round2_secret_package: &round2::SecretPackage,
            round1_packages: &[round1::Package],
            round2_packages: &[round2::Package],
        ) -> Result<(KeyPackage, PublicKeyPackage), Error> {
            let (secret, pubkey) = frost_secp256k1::keys::dkg::part3(
                round2_secret_package,
                round1_packages,
                round2_packages,
            )?;
            VerifyingKey::new(pubkey.group_public)?;
            Ok((secret, pubkey))
        }
    }
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
    /// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-round-two-signature-share-g
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &SigningNonces,
        key_package: &KeyPackage,
    ) -> Result<SignatureShare, Error> {
        VerifyingKey::new(key_package.group_public)?;

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list = compute_binding_factor_list(signing_package, &[]);
        let binding_factor = binding_factor_list[key_package.identifier].clone();

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

        // Compute Lagrange coefficient.
        let lambda_i = derive_interpolating_value(key_package.identifier(), signing_package)?;

        // Compute the per-message challenge.
        let challenge = challenge(
            to_address(group_commitment.to_element()),
            &key_package.group_public.to_element(),
            signing_package.message().as_slice(),
        );

        // Compute the Schnorr signature share.
        let signature_share = compute_signature_share(
            signer_nonces,
            binding_factor,
            lambda_i,
            key_package,
            Challenge::from_scalar(-challenge),
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
    signature_shares: &[SignatureShare],
    pubkeys: &PublicKeyPackage,
) -> Result<Signature, Error> {
    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list = compute_binding_factor_list(signing_package, &[]);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-5.3
    let mut z = Scalar::ZERO;

    for signature_share in signature_shares {
        z += signature_share.signature.z_share;
    }

    let signature = Signature::new(group_commitment.clone().to_element(), z);

    // Verify the aggregate signature
    let verification_result =
        VerifyingKey::new(pubkeys.group_public)?.verify(signing_package.message(), &signature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if let Err(err) = verification_result {
        // Compute the per-message challenge.
        let challenge = challenge(
            to_address(group_commitment.to_element()),
            &pubkeys.group_public.to_element(),
            signing_package.message().as_slice(),
        );

        // Verify the signature shares.
        for signature_share in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .signer_pubkeys
                .get(&signature_share.identifier)
                .unwrap();

            // Compute Lagrange coefficient.
            let lambda_i =
                derive_interpolating_value(&signature_share.identifier, signing_package)?;

            let binding_factor = binding_factor_list[signature_share.identifier].clone();

            // Compute the commitment share.
            let r_share = signing_package
                .signing_commitment(&signature_share.identifier)
                .to_group_commitment_share(&binding_factor);

            // Compute relation values to verify this signature share.
            signature_share.verify(
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
