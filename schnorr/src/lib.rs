#![cfg_attr(not(feature = "std"), no_std)]
pub use k256;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, NonZeroScalar, ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::Digest;

pub mod proof_of_knowledge;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;

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
        let e: &k256::FieldBytes = bytes[..32].try_into().unwrap();
        let e = Option::from(Scalar::from_repr(*e)).ok_or(Error::InvalidSignature)?;
        let z: &k256::FieldBytes = bytes[32..].try_into().unwrap();
        let z = Option::from(Scalar::from_repr(*z)).ok_or(Error::InvalidSignature)?;
        Ok(Self { e, z })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().as_ref())
    }
}

#[cfg(feature = "serde")]
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

#[derive(Clone, Copy)]
pub struct SigningKey {
    scalar: NonZeroScalar,
}

impl SigningKey {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            scalar: NonZeroScalar::random(rng),
        }
    }

    #[cfg(feature = "std")]
    pub fn random() -> Self {
        Self::new(&mut rand_core::OsRng)
    }

    pub fn to_scalar(&self) -> NonZeroScalar {
        self.scalar
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes().into()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let scalar =
            Option::from(NonZeroScalar::from_repr(bytes.into())).ok_or(Error::InvalidSecretKey)?;
        Ok(Self { scalar })
    }

    pub fn public(&self) -> VerifyingKey {
        VerifyingKey::new(AffinePoint::GENERATOR * self.scalar.as_ref())
    }

    pub fn sign_prehashed_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        hash: [u8; 32],
    ) -> Signature {
        let k = NonZeroScalar::random(rng);
        let r = AffinePoint::GENERATOR * k.as_ref();
        let public = self.public();
        let c = public.challenge(hash, r);
        let z = k.as_ref() + c * self.scalar.as_ref();
        Signature::new(c, z)
    }

    #[cfg(feature = "std")]
    pub fn sign_prehashed(&self, hash: [u8; 32]) -> Signature {
        self.sign_prehashed_with_rng(&mut rand_core::OsRng, hash)
    }

    #[cfg(feature = "std")]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let hash = VerifyingKey::message_hash(msg);
        self.sign_prehashed(hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VerifyingKey {
    element: ProjectivePoint,
}

impl VerifyingKey {
    pub fn new(element: ProjectivePoint) -> Self {
        Self { element }
    }

    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, Error> {
        let point = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        let point: AffinePoint =
            Option::from(AffinePoint::from_encoded_point(&point)).ok_or(Error::InvalidPublicKey)?;
        if point.is_identity().into() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self::new(ProjectivePoint::from(point)))
    }

    pub fn to_bytes(self) -> Result<[u8; 33], Error> {
        let point = self.to_affine().to_encoded_point(true);
        // can only happen if we encode the identity
        point
            .as_bytes()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)
    }

    pub fn to_element(self) -> ProjectivePoint {
        self.element
    }

    fn to_affine(self) -> AffinePoint {
        self.element.to_affine()
    }

    pub fn to_px_parity(self) -> ([u8; 32], u8) {
        let affine = self.to_affine();
        (affine.x().into(), affine.y_is_odd().unwrap_u8() + 27)
    }

    pub fn message_hash(message: &[u8]) -> [u8; 32] {
        sha3::Keccak256::digest(message).into()
    }

    pub fn challenge(self, message_hash: [u8; 32], r: ProjectivePoint) -> Scalar {
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

    pub fn verify_prehashed(
        self,
        message_hash: [u8; 32],
        signature: &Signature,
    ) -> Result<(), Error> {
        let r = AffinePoint::GENERATOR * signature.z - self.element * signature.e;
        let ep = self.challenge(message_hash, r);
        if signature.e != ep {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify(self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify_prehashed(Self::message_hash(message), signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let key = SigningKey::random();
        let public = key.public();
        let sig = key.sign(b"hello world");
        public.verify(b"hello world", &sig).unwrap();
    }
}
