use frost_core::round2::compute_signature_share;
use frost_core::{
    compute_binding_factor_list, compute_group_commitment, derive_interpolating_value, Challenge,
};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::round1::SigningNonces;
use frost_secp256k1::round2::SignatureShare;
use std::collections::HashMap;

pub type Scalar = frost_core::Scalar<frost_secp256k1::Secp256K1Sha256>;
#[cfg(feature = "serde")]
pub type ScalarSerialization = frost_core::ScalarSerialization<frost_secp256k1::Secp256K1Sha256>;

pub use frost_core;
pub use frost_secp256k1;
pub use frost_secp256k1::round1;
pub use frost_secp256k1::{Error, Identifier, SigningKey, SigningPackage};
pub use schnorr_evm as schnorr;
pub use schnorr_evm::*;

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
        if signing_package.signing_commitments().len() < *key_package.min_signers() as usize {
            return Err(Error::IncorrectNumberOfCommitments);
        }

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
            compute_binding_factor_list(signing_package, key_package.verifying_key(), &[]);
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
        let group_public = VerifyingKey::new(key_package.verifying_key().to_element());
        let challenge = Challenge::from_scalar(group_public.challenge(
            VerifyingKey::message_hash(signing_package.message().as_slice()),
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
    // Check if signing_package.signing_commitments and signature_shares have
    // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
    if signing_package.signing_commitments().len() != signature_shares.len() {
        return Err(Error::UnknownIdentifier);
    }
    if !signing_package.signing_commitments().keys().all(|id| {
        return signature_shares.contains_key(id) && pubkeys.verifying_shares().contains_key(id);
    }) {
        return Err(Error::UnknownIdentifier);
    }

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list =
        compute_binding_factor_list(signing_package, pubkeys.verifying_key(), &[]);

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

    let group_public = VerifyingKey::new(pubkeys.verifying_key().to_element());
    let challenge = group_public.challenge(
        VerifyingKey::message_hash(signing_package.message().as_slice()),
        group_commitment.to_element(),
    );

    let signature = Signature::new(challenge, z);

    // Verify the aggregate signature
    let verification_result = group_public
        .verify(signing_package.message(), &signature)
        .map_err(|_| Error::MalformedSignature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if let Err(err) = verification_result {
        // Verify the signature shares.
        for (signature_share_identifier, signature_share) in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .verifying_shares()
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
