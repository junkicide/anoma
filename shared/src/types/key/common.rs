//! Cryptographic keys

use super::{ed25519c, secp256k1};
use super::{ParsePublicKeyError, VerifySigError, SchemeType, IntoRef, TryFromRef, ParseSecretKeyError, ParseKeypairError, ParseSignatureError, SigScheme as SigSchemeTrait};
use std::fmt::Display;
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use std::str::FromStr;

/// Public key
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum PublicKey {
    /// Encapsulate Ed25519 public keys
    Ed25519(ed25519c::PublicKey),
    /// Encapsulate Secp256k1 public keys
    Secp256k1(secp256k1::PublicKey),
}

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;
    fn try_from_pk<PK: super::PublicKey>(pk: &PK) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParsePublicKeyError::InvalidEncoding)
        } else if PK::TYPE == ed25519c::PublicKey::TYPE {
            Ok(Self::Ed25519(ed25519c::PublicKey::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParsePublicKeyError::InvalidEncoding)?))
        } else if PK::TYPE == secp256k1::PublicKey::TYPE {
            Ok(Self::Secp256k1(secp256k1::PublicKey::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParsePublicKeyError::InvalidEncoding)?))
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.try_to_vec().unwrap()))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(str).map_err(ParsePublicKeyError::InvalidHex)?;
        Self::try_from_slice(vec.as_slice()).map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

/// Secret key
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum SecretKey {
    /// Encapsulate Ed25519 secret keys
    Ed25519(ed25519c::SecretKey),
    /// Encapsulate Secp256k1 secret keys
    Secp256k1(secp256k1::SecretKey),
}

impl super::SecretKey for SecretKey {
    const TYPE: SchemeType = SigScheme::TYPE;
    fn try_from_sk<PK: super::SecretKey>(pk: &PK) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_ref()).map_err(ParseSecretKeyError::InvalidEncoding)
        } else if PK::TYPE == ed25519c::SecretKey::TYPE {
            Ok(Self::Ed25519(ed25519c::SecretKey::try_from_slice(pk.try_to_vec().unwrap().as_ref()).map_err(ParseSecretKeyError::InvalidEncoding)?))
        } else if PK::TYPE == secp256k1::SecretKey::TYPE {
            Ok(Self::Secp256k1(secp256k1::SecretKey::try_from_slice(pk.try_to_vec().unwrap().as_ref()).map_err(ParseSecretKeyError::InvalidEncoding)?))
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.try_to_vec().unwrap()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(str).map_err(ParseSecretKeyError::InvalidHex)?;
        Self::try_from_slice(vec.as_slice()).map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

/// Signature
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum Signature {
    /// Encapsulate Ed25519 signatures
    Ed25519(ed25519c::Signature),
    /// Encapsulate Secp256k1 signatures
    Secp256k1(secp256k1::Signature),
}

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;
    fn try_from_sig<PK: super::Signature>(pk: &PK) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParseSignatureError::InvalidEncoding)
        } else if PK::TYPE == ed25519c::Signature::TYPE {
            Ok(Self::Ed25519(ed25519c::Signature::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParseSignatureError::InvalidEncoding)?))
        } else if PK::TYPE == secp256k1::Signature::TYPE {
            Ok(Self::Secp256k1(secp256k1::Signature::try_from_slice(pk.try_to_vec().unwrap().as_ref()).map_err(ParseSignatureError::InvalidEncoding)?))
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

/// Keypair
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum Keypair {
    /// Encapsulate Ed25519 keypairs
    Ed25519(ed25519c::Keypair),
    /// Encapsulate Secp256k1 keypairs
    Secp256k1(secp256k1::Keypair),
}

impl super::Keypair for Keypair {
    const TYPE: SchemeType = SigScheme::TYPE;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    fn try_from_kp<PK: super::Keypair>(pk: &PK) -> Result<Self, ParseKeypairError> {
        let buf = pk.try_to_vec().unwrap();
        if PK::TYPE == Self::TYPE {
            Self::try_from_slice(buf.as_slice()).map_err(ParseKeypairError::InvalidEncoding)
        } else if PK::TYPE == ed25519c::Keypair::TYPE {
            Ok(Self::Ed25519(ed25519c::Keypair::try_from_slice(buf.as_slice()).map_err(ParseKeypairError::InvalidEncoding)?))
        } else if PK::TYPE == secp256k1::Keypair::TYPE {
            Ok(Self::Secp256k1(secp256k1::Keypair::try_from_slice(buf.as_slice()).map_err(ParseKeypairError::InvalidEncoding)?))
        } else {
            Err(ParseKeypairError::MismatchedScheme)
        }
    }
}

impl Display for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.try_to_vec().unwrap()))
    }
}

impl IntoRef<(PublicKey, SecretKey)> for Keypair {
    fn into_ref(&self) -> (PublicKey, SecretKey) {
        match self {
            Keypair::Ed25519(kp) => {
                let (pk, sk) = kp.into_ref();
                (PublicKey::Ed25519(pk), SecretKey::Ed25519(sk))
            }, Keypair::Secp256k1(kp) => {
                let (pk, sk) = kp.into_ref();
                (PublicKey::Secp256k1(pk), SecretKey::Secp256k1(sk))
            }
        }
    }
}

impl TryFromRef<(PublicKey, SecretKey)> for Keypair {
    type Error = ParseKeypairError;
    fn try_from_ref(kp: &(PublicKey, SecretKey)) -> Result<Self, Self::Error> {
        match kp.clone() {
            (PublicKey::Ed25519(pk), SecretKey::Ed25519(sk)) => {
                TryFromRef::try_from_ref(&(pk, sk)).map(Keypair::Ed25519)
            },
            (PublicKey::Secp256k1(pk), SecretKey::Secp256k1(sk)) => {
                TryFromRef::try_from_ref(&(pk, sk)).map(Keypair::Secp256k1)
            },
            _ => Err(ParseKeypairError::MismatchedScheme),
        }
    }
}

impl FromStr for Keypair {
    type Err = ParseKeypairError;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(str).map_err(ParseKeypairError::InvalidHex)?;
        Self::try_from_slice(vec.as_slice()).map_err(ParseKeypairError::InvalidEncoding)
    }
}

/// An implementation of the common signature scheme
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Default,
)]
pub struct SigScheme;

impl super::SigScheme for SigScheme {
    type Keypair = Keypair;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    const TYPE: SchemeType = SchemeType::Common;
    
    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R, sch: SchemeType) -> Option<Keypair>
    where
        R: CryptoRng + RngCore,
    {
        if sch == ed25519c::SigScheme::TYPE {
            ed25519c::SigScheme::generate(csprng, sch).map(Keypair::Ed25519)
        } else if sch == secp256k1::SigScheme::TYPE {
            secp256k1::SigScheme::generate(csprng, sch).map(Keypair::Secp256k1)
        } else { None }
    }

    fn sign(keypair: &Keypair, data: impl AsRef<[u8]>) -> Self::Signature {
        match keypair {
            Keypair::Ed25519(kp) =>
                Signature::Ed25519(ed25519c::SigScheme::sign(kp, data)),
            Keypair::Secp256k1(kp) =>
                Signature::Secp256k1(secp256k1::SigScheme::sign(kp, data)),
        }
    }

    fn verify_signature<T: BorshSerialize + BorshDeserialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        match (pk, sig) {
            (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) =>
                ed25519c::SigScheme::verify_signature(pk, data, sig),
            (PublicKey::Secp256k1(pk), Signature::Secp256k1(sig)) =>
                secp256k1::SigScheme::verify_signature(pk, data, sig),
            _ => Err(VerifySigError::MismatchedScheme),
        }
    }

    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        match (pk, sig) {
            (PublicKey::Ed25519(pk), Signature::Ed25519(sig)) =>
                ed25519c::SigScheme::verify_signature_raw(pk, data, sig),
            (PublicKey::Secp256k1(pk), Signature::Secp256k1(sig)) =>
                secp256k1::SigScheme::verify_signature_raw(pk, data, sig),
            _ => Err(VerifySigError::MismatchedScheme),
        }
    }
}
