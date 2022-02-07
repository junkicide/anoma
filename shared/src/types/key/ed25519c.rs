//! Ed25519 keys and related functionality

use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Write};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    ParsePublicKeyError, IntoRef, TryFromRef, VerifySigError, SchemeType, Repr, ParseSecretKeyError, ParseKeypairError, ParseSignatureError, SigScheme as SigSchemeTrait
};

/// Ed25519 public key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub ed25519_consensus::VerificationKey);

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(pk: &PK) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == super::common::PublicKey::TYPE {
            super::common::PublicKey::try_from_pk(pk).and_then(|x| match x {
                super::common::PublicKey::Ed25519(epk) => Ok(epk),
                _ => Err(ParsePublicKeyError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_ref(pk.into_ref().as_ref())
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

impl Repr<[u8]> for PublicKey {
    const LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
    type T = [u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
}

impl IntoRef<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> for PublicKey {
    fn into_ref(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }
}

impl TryFromRef<[u8]> for PublicKey {
    type Error = ParsePublicKeyError;
    fn try_from_ref(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(ed25519_consensus::VerificationKey::try_from(bytes).map_err(|err| ParsePublicKeyError::InvalidEncoding(std::io::Error::new(ErrorKind::InvalidInput, err)))?))
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ok(PublicKey(ed25519_consensus::VerificationKey::try_from(<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] as BorshDeserialize>::deserialize(buf)?.as_ref()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes()
            .hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_bytes()
            .partial_cmp(
                &other.0.to_bytes(),
            )
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes()
            .cmp(
                &other.0.to_bytes(),
            )
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0.to_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParsePublicKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParsePublicKeyError::InvalidEncoding)
    }
}

/// Ed25519 secret key
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKey(pub ed25519_consensus::SigningKey);

impl super::SecretKey for SecretKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sk<PK: super::SecretKey>(pk: &PK) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == super::common::SecretKey::TYPE {
            super::common::SecretKey::try_from_sk(pk).and_then(|x| match x {
                super::common::SecretKey::Ed25519(epk) => Ok(epk),
                _ => Err(ParseSecretKeyError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_ref(pk.into_ref().as_ref())
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        SecretKey(ed25519_consensus::SigningKey::from(self.0.to_bytes()))
    }
}

impl Repr<[u8]> for SecretKey {
    const LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
    type T = [u8; ed25519_dalek::SECRET_KEY_LENGTH];
}

impl IntoRef<[u8; ed25519_dalek::SECRET_KEY_LENGTH]> for SecretKey {
    fn into_ref(&self) -> [u8; ed25519_dalek::SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }
}

impl TryFromRef<[u8]> for SecretKey {
    type Error = ParseSecretKeyError;
    fn try_from_ref(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(ed25519_consensus::SigningKey::try_from(bytes).map_err(|err| ParseSecretKeyError::InvalidEncoding(std::io::Error::new(ErrorKind::InvalidInput, err)))?))
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ok(SecretKey(ed25519_consensus::SigningKey::try_from(<[u8; ed25519_dalek::SECRET_KEY_LENGTH] as BorshDeserialize>::deserialize(buf)?.as_ref()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?))
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0.to_bytes()))
    }
}

impl FromStr for SecretKey {
    type Err = ParseSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParseSecretKeyError::InvalidHex)?;
        BorshDeserialize::try_from_slice(&vec)
            .map_err(ParseSecretKeyError::InvalidEncoding)
    }
}

/// Ed25519 keypair
#[derive(Debug, Clone)]
pub struct Keypair(pub ed25519_consensus::VerificationKey, pub ed25519_consensus::SigningKey);

impl super::Keypair for Keypair {
    const TYPE: SchemeType = SigScheme::TYPE;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn try_from_kp<PK: super::Keypair>(pk: &PK) -> Result<Self, ParseKeypairError> {
        if PK::TYPE == super::common::Keypair::TYPE {
            super::common::Keypair::try_from_kp(pk).and_then(|x| match x {
                super::common::Keypair::Ed25519(epk) => Ok(epk),
                _ => Err(ParseKeypairError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            let buf: PK::T = pk.into_ref();
            Self::try_from_ref(buf.as_ref())
        } else {
            Err(ParseKeypairError::MismatchedScheme)
        }
    }
}

impl Repr<[u8]> for Keypair {
    const LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH + ed25519_dalek::PUBLIC_KEY_LENGTH;
    type T = [u8; Self::LENGTH];
}

impl IntoRef<<Self as Repr<[u8]>>::T> for Keypair {
    fn into_ref(&self) -> <Self as Repr<[u8]>>::T {
        let mut arr = [0; Self::LENGTH];
        arr[..ed25519_dalek::SECRET_KEY_LENGTH].copy_from_slice(self.1.as_bytes());
        arr[ed25519_dalek::SECRET_KEY_LENGTH..].copy_from_slice(self.0.as_bytes());
        arr
    }
}

impl IntoRef<(PublicKey, SecretKey)> for Keypair {
    fn into_ref(&self) -> (PublicKey, SecretKey) {
        (PublicKey(self.0), SecretKey(self.1))
    }
}

impl TryFromRef<(PublicKey, SecretKey)> for Keypair {
    type Error = ParseKeypairError;
    fn try_from_ref(kp: &(PublicKey, SecretKey)) -> Result<Self, Self::Error> {
        Ok(Self(kp.0.0, kp.1.0))
    }
}

impl TryFromRef<[u8]> for Keypair {
    type Error = ParseKeypairError;
    fn try_from_ref(bytes: &[u8]) -> Result<Self, Self::Error> {
        let hdl = |err| ParseKeypairError::InvalidEncoding(std::io::Error::new(ErrorKind::InvalidInput, err));
        let sk: ed25519_consensus::SigningKey = bytes[..ed25519_dalek::SECRET_KEY_LENGTH].try_into().map_err(hdl)?;
        let pk: ed25519_consensus::VerificationKey = bytes[ed25519_dalek::SECRET_KEY_LENGTH..].try_into().map_err(hdl)?;
        if pk == sk.verification_key() {
            Ok(Keypair(pk, sk))
        } else {
            Err(ParseKeypairError::MismatchedParts)
        }
    }
}

impl BorshSerialize for Keypair {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.1.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl BorshDeserialize for Keypair {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let hdl = |e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
        let sk: ed25519_consensus::SigningKey = <[u8; ed25519_dalek::SECRET_KEY_LENGTH] as BorshDeserialize>::deserialize(buf)?.into();
        let pk: ed25519_consensus::VerificationKey = <[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] as BorshDeserialize>::deserialize(buf)?.try_into().map_err(hdl)?;
        if pk == sk.verification_key() {
            Ok(Keypair(pk, sk))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, ParseKeypairError::MismatchedParts))
        }
    }
}

impl Display for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes: <Self as Repr<[u8]>>::T = self.into_ref();
        write!(f, "{}", hex::encode(bytes.as_ref()))
    }
}

impl FromStr for Keypair {
    type Err = ParseKeypairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(ParseKeypairError::InvalidHex)?;
        Keypair::try_from_ref(vec.as_slice())
    }
}

/// Ed25519 signature
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature(pub ed25519_consensus::Signature);

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<PK: super::Signature>(pk: &PK) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == super::common::Signature::TYPE {
            super::common::Signature::try_from_sig(pk).and_then(|x| match x {
                super::common::Signature::Ed25519(epk) => Ok(epk),
                _ => Err(ParseSignatureError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_ref(pk.into_ref().as_ref())
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

impl Repr<[u8]> for Signature {
    const LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;
    type T = [u8; ed25519_dalek::SIGNATURE_LENGTH];
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ok(Signature(ed25519_consensus::Signature::try_from(<[u8; ed25519_dalek::SIGNATURE_LENGTH] as BorshDeserialize>::deserialize(buf)?.as_ref()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.to_bytes().serialize(writer)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes()
            .hash(state);
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_bytes()
            .partial_cmp(
                &other.0.to_bytes(),
            )
    }
}

impl IntoRef<[u8; ed25519_dalek::SIGNATURE_LENGTH]> for Signature {
    fn into_ref(&self) -> [u8; ed25519_dalek::SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }
}

impl TryFromRef<[u8]> for Signature {
    type Error = ParseSignatureError;
    fn try_from_ref(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Signature(ed25519_consensus::Signature::try_from(bytes).map_err(|err| ParseSignatureError::InvalidEncoding(std::io::Error::new(ErrorKind::InvalidInput, err)))?))
    }
}

/// An implementation of the Ed25519 signature scheme
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
    
    const TYPE: SchemeType = SchemeType::Ed25519Consensus;
    
    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R, sch: SchemeType) -> Option<Keypair>
    where
        R: CryptoRng + RngCore,
    {
        if sch == Self::TYPE {
            let sk = ed25519_consensus::SigningKey::new(csprng);
            Some(Keypair((&sk).into(), sk))
        } else { None }
    }

    fn sign(keypair: &Keypair, data: impl AsRef<[u8]>) -> Self::Signature {
        Signature((&keypair.1).sign(data.as_ref()))
    }

    fn verify_signature<T: BorshSerialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        let bytes = data.try_to_vec().map_err(VerifySigError::DataEncodingError)?;
        pk.0.verify(&sig.0, &bytes)
            .map_err(|err| VerifySigError::SigVerifyError(err.to_string()))
    }

    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        pk.0.verify(&sig.0, data)
            .map_err(|err| VerifySigError::SigVerifyError(err.to_string()))
    }
}
