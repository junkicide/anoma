//! Secp256k1 keys and related functionality

use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde::de::{Visitor, Error, SeqAccess};
use serde::ser::SerializeTuple;
use std::fmt;
use std::str::FromStr;
use super::{ParsePublicKeyError, ParseSecretKeyError, ParseSignatureError, VerifySigError, ToRef, SchemeType, SigScheme as SigSchemeTrait};
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};

/// Secp256k1 public key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(libsecp256k1::PublicKey);

impl super::PublicKey for PublicKey {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_pk<PK: super::PublicKey>(pk: &PK) -> Result<Self, ParsePublicKeyError> {
        if PK::TYPE == super::common::PublicKey::TYPE {
            super::common::PublicKey::try_from_pk(pk).and_then(|x| match x {
                super::common::PublicKey::Secp256k1(epk) => Ok(epk),
                _ => Err(ParsePublicKeyError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParsePublicKeyError::InvalidEncoding)
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
}

impl From<libsecp256k1::PublicKey> for PublicKey {
    fn from(pk: libsecp256k1::PublicKey) -> Self {
        Self(pk)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.serialize()
            .hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.serialize()
            .partial_cmp(
                &other.0.serialize(),
            )
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.serialize()
            .cmp(
                &other.0.serialize(),
            )
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0.serialize()))
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

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        Ok(PublicKey(libsecp256k1::PublicKey::parse(&(BorshDeserialize::deserialize(buf)?)).map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, format!("Error decoding secp256k1 public key: {}", e)))?))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.serialize(), writer)
    }
}

/// Secp256k1 secret key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey(libsecp256k1::SecretKey);

impl super::SecretKey for SecretKey {
    const TYPE: SchemeType = SigScheme::TYPE;
    type PublicKey = PublicKey;

    fn try_from_sk<PK: super::SecretKey>(pk: &PK) -> Result<Self, ParseSecretKeyError> {
        if PK::TYPE == super::common::SecretKey::TYPE {
            super::common::SecretKey::try_from_sk(pk).and_then(|x| match x {
                super::common::SecretKey::Secp256k1(epk) => Ok(epk),
                _ => Err(ParseSecretKeyError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParseSecretKeyError::InvalidEncoding)
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
}

impl ToRef<PublicKey> for SecretKey {
    fn to_ref(&self) -> PublicKey {
        PublicKey(libsecp256k1::PublicKey::from_secret_key(&self.0))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0.serialize()))
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

impl BorshDeserialize for SecretKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        Ok(SecretKey(libsecp256k1::SecretKey::parse(&(BorshDeserialize::deserialize(buf)?)).map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, format!("Error decoding secp256k1 secret key: {}", e)))?))
    }
}

impl BorshSerialize for SecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.serialize(), writer)
    }
}

/// Secp256k1 signature
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(libsecp256k1::Signature);

impl super::Signature for Signature {
    const TYPE: SchemeType = SigScheme::TYPE;

    fn try_from_sig<PK: super::Signature>(pk: &PK) -> Result<Self, ParseSignatureError> {
        if PK::TYPE == super::common::Signature::TYPE {
            super::common::Signature::try_from_sig(pk).and_then(|x| match x {
                super::common::Signature::Secp256k1(epk) => Ok(epk),
                _ => Err(ParseSignatureError::MismatchedScheme)
            })
        } else if PK::TYPE == Self::TYPE {
            Self::try_from_slice(pk.try_to_vec().unwrap().as_slice()).map_err(ParseSignatureError::InvalidEncoding)
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let arr = self.0.serialize();
        let mut seq = serializer.serialize_tuple(arr.len())?;
        for elem in &arr[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArrayVisitor;

        impl<'de> Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 64))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 64], A::Error>
            where A: SeqAccess<'de> {
                let mut arr = [0; 64];
                for i in 0..64 {
                    arr[i] = seq.next_element()?.ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        
        let arr_res = deserializer.deserialize_tuple(64, ByteArrayVisitor)?;
        let sig = libsecp256k1::Signature::parse_standard(&arr_res).map_err(D::Error::custom)?;
        Ok(Signature(sig))
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        Ok(Signature(libsecp256k1::Signature::parse_standard(&(BorshDeserialize::deserialize(buf)?)).map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, format!("Error decoding secp256k1 signature: {}", e)))?))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.serialize(), writer)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.serialize()
            .hash(state);
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.serialize()
            .partial_cmp(
                &other.0
                    .serialize(),
            )
    }
}

/// An implementation of the Secp256k1 signature scheme
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
    const TYPE: SchemeType = SchemeType::Secp256k1;
    
    type Signature = Signature;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn generate<R>(csprng: &mut R, sch: SchemeType) -> Option<Self::SecretKey>
    where R: CryptoRng + RngCore {
        if sch == Self::TYPE {
            Some(SecretKey(libsecp256k1::SecretKey::random(csprng)))
        } else {
            None
        }
    }
    
    /// Sign the data with a key.
    fn sign(keypair: &SecretKey, data: impl AsRef<[u8]>) -> Signature {
        let message_to_sign = libsecp256k1::Message::parse_slice(&data.as_ref())
            .expect("Message encoding shouldn't fail");
        Signature(libsecp256k1::sign(&message_to_sign, &keypair.0).0)
    }

    /// Check that the public key matches the signature on the given data.
    fn verify_signature<T: BorshSerialize + BorshDeserialize>(
        pk: &PublicKey,
        data: &T,
        sig: &Signature,
    ) -> Result<(), VerifySigError> {
        let bytes = &data.try_to_vec().map_err(VerifySigError::DataEncodingError)?[..];
        let message = &libsecp256k1::Message::parse_slice(bytes).expect("Error parsing given data");
        let check = libsecp256k1::verify(message, &sig.0, &pk.0);
        match check {
            true => Ok(()),
            false => Err(VerifySigError::SigVerifyError(format!("Error verifying secp256k1 signature: {}", libsecp256k1::Error::InvalidSignature)))
        }
    }

    /// Check that the public key matches the signature on the given raw data.
    fn verify_signature_raw(
        pk: &PublicKey,
        data: &[u8],
        sig: &Signature,
    ) -> Result<(), VerifySigError> {
        let message = &libsecp256k1::Message::parse_slice(data)
            .expect("Error parsing raw data");
        let check = libsecp256k1::verify(message, &sig.0, &pk.0);
        match check {
            true => Ok(()),
            false => Err(VerifySigError::SigVerifyError(format!("Error verifying secp256k1 signature: {}", libsecp256k1::Error::InvalidSignature)))
        }
    }
}
