use k256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, Scalar};
use sha2::Sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCommitment,
    InvalidProofOfKnowledge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::InvalidCommitment => write!(f, "invalid commitment"),
            Self::InvalidProofOfKnowledge => write!(f, "invalid proof of knowledge"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub type ProofOfKnowledge = [u8; 65];
pub type Commitment = [[u8; 33]];

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-1
const ID_CONTEXT_STRING: &str = "FROST-secp256k1-SHA256-v1id";
const DKG_CONTEXT_STRING: &str = "FROST-secp256k1-SHA256-v1dkg";

fn hash_to_scalar(domain: &str, msg: &[u8]) -> Scalar {
    let mut u = [Scalar::ZERO];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], &[domain.as_bytes()], &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0]
}

pub fn verify_proof_of_knowledge(
    peer: &[u8],
    commitment: &Commitment,
    pok: ProofOfKnowledge,
) -> Result<()> {
    if commitment.is_empty() {
        return Err(Error::InvalidCommitment);
    }
    let pk = commitment[0];
    let r: [u8; 33] = pok[..33].try_into().unwrap();
    let z: [u8; 32] = pok[33..].try_into().unwrap();
    let id = hash_to_scalar(ID_CONTEXT_STRING, peer);

    let mut preimage = [0; 98];
    preimage[..32].copy_from_slice(&id.to_bytes());
    preimage[32..65].copy_from_slice(&pk);
    preimage[65..].copy_from_slice(&r);
    let c = hash_to_scalar(DKG_CONTEXT_STRING, &preimage[..]);

    let pk = EncodedPoint::from_bytes(pk).map_err(|_| Error::InvalidCommitment)?;
    let pk = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&pk))
        .ok_or(Error::InvalidCommitment)?;
    let r = EncodedPoint::from_bytes(r).map_err(|_| Error::InvalidProofOfKnowledge)?;
    let r = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&r))
        .ok_or(Error::InvalidProofOfKnowledge)?;
    let z = Option::<Scalar>::from(Scalar::from_repr(z.into()))
        .ok_or(Error::InvalidProofOfKnowledge)?;
    if r != AffinePoint::GENERATOR * z - pk * c {
        return Err(Error::InvalidProofOfKnowledge);
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn construct_proof_of_knowledge(
    peer: &[u8],
    coefficients: &[Scalar],
    commitment: &Commitment,
) -> Result<ProofOfKnowledge, frost_core::Error<frost_secp256k1::Secp256K1Sha256>> {
    let sig = frost_core::keys::dkg::compute_proof_of_knowledge(
        frost_core::Identifier::derive(peer)?,
        coefficients,
        &frost_core::keys::VerifiableSecretSharingCommitment::deserialize(commitment.to_vec())?,
        rand_core::OsRng,
    )?;
    Ok(sig.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::NonZeroScalar;

    #[test]
    fn test_verify() {
        let rng = &mut rand_core::OsRng;
        let peer = b"some peer id";
        let n = 3;
        let mut coefficients = Vec::with_capacity(n);
        let mut commitments = Vec::with_capacity(n);
        for _ in 0..n {
            let coefficient = *NonZeroScalar::random(rng).as_ref();
            let commitment = AffinePoint::GENERATOR * coefficient;
            let point = commitment.to_affine().to_encoded_point(true);
            let bytes = point.as_bytes().try_into().unwrap();
            coefficients.push(coefficient);
            commitments.push(bytes);
        }
        let pok = construct_proof_of_knowledge(peer, &coefficients, &commitments).unwrap();
        verify_proof_of_knowledge(peer, &commitments, pok).unwrap();
    }
}
