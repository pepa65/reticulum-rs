use hkdf::Hkdf;
use rand_core::CryptoRngCore;

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::{
    crypt::fernet::{Fernet, PlainText, Token},
    error::RnsError,
    hash::{AddressHash, Hash},
};

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

pub trait EncryptIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait DecryptIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait HashIdentity {
    fn as_address_hash_slice(&self) -> &[u8];
}

#[derive(Copy, Clone)]
pub struct Identity {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
    pub address_hash: AddressHash,
}

impl Identity {
    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(public_key.as_bytes())
                .chain_update(verifying_key.as_bytes())
                .finalize()
                .into(),
        );

        let address_hash = AddressHash::new_from_hash(&hash);

        Self {
            public_key,
            verifying_key,
            address_hash,
        }
    }

    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.public_key.as_bytes()
    }

    pub fn verifying_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.as_bytes()
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.verifying_key
            .verify_strict(data, signature)
            .map_err(|_| RnsError::IncorrectSignature)
    }
}

impl HashIdentity for Identity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.address_hash.as_slice()
    }
}

impl EncryptIdentity for Identity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let mut out_offset = 0;
        let ephemeral_key = EphemeralSecret::random_from_rng(rng);
        {
            let ephemeral_public = PublicKey::from(&ephemeral_key);
            let ephemeral_public_bytes = ephemeral_public.as_bytes();

            if out_buf.len() >= ephemeral_public_bytes.len() {
                out_buf[..ephemeral_public_bytes.len()].copy_from_slice(ephemeral_public_bytes);
                out_offset += ephemeral_public_bytes.len();
            } else {
                return Err(RnsError::InvalidArgument);
            }
        }

        let derived_key = create_derived_key(
            &ephemeral_key.diffie_hellman(&self.public_key),
            Some(self.address_hash.as_slice()),
        );

        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..16],
            &derived_key.as_bytes()[16..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.as_bytes().len();

        Ok(&out_buf[..out_offset])
    }
}

pub struct EmptyIdentity;

impl HashIdentity for EmptyIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        &[]
    }
}

impl EncryptIdentity for EmptyIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if text.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..text.len()];
        result.copy_from_slice(&text);
        Ok(result)
    }
}

impl DecryptIdentity for EmptyIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if data.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..data.len()];
        result.copy_from_slice(&data);
        Ok(result)
    }
}

pub struct PrivateIdentity {
    identity: Identity,
    private_key: StaticSecret,
    sign_key: SigningKey,
}

impl PrivateIdentity {
    pub fn new(private_key: StaticSecret, sign_key: SigningKey) -> Self {
        Self {
            identity: Identity::new((&private_key).into(), sign_key.verifying_key()),
            private_key,
            sign_key,
        }
    }

    pub fn new_from_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let sign_key = SigningKey::generate(&mut rng);
        let private_key = StaticSecret::random_from_rng(rng);

        Self::new(private_key, sign_key)
    }

    pub fn into(&self) -> &Identity {
        &self.identity
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn address_hash(&self) -> &AddressHash {
        &self.identity.address_hash
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.identity.verify(data, signature)
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, RnsError> {
        self.sign_key
            .try_sign(data)
            .map_err(|_| RnsError::IncorrectSignature)
    }
}

impl HashIdentity for PrivateIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.identity.address_hash.as_slice()
    }
}

impl EncryptIdentity for PrivateIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        self.identity.encrypt(rng, text, out_buf)
    }
}

impl DecryptIdentity for PrivateIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if data.len() <= PUBLIC_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let public_key = {
            let mut public_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
            public_key_bytes[..].copy_from_slice(&data[..PUBLIC_KEY_LENGTH]);
            PublicKey::from(public_key_bytes)
        };

        let derived_key = create_derived_key(
            &self.private_key.diffie_hellman(&public_key),
            Some(self.identity.address_hash.as_slice()),
        );

        let mut fernet = Fernet::new_from_slices(
            &derived_key.as_bytes()[..16],
            &derived_key.as_bytes()[16..],
            rng,
        );

        let token = Token::from(&data[PUBLIC_KEY_LENGTH..]);

        let token = fernet.verify(token)?;

        let plain_text = fernet.decrypt(token, out_buf)?;

        Ok(plain_text.as_slice())
    }
}

pub struct GroupIdentity {}

fn create_derived_key(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Hash {
    let mut derived_key = Hash::new_empty();

    let _ =
        Hkdf::<Sha256>::new(salt, shared_key.as_bytes()).expand(&[], derived_key.as_slice_mut());

    derived_key
}

#[cfg(test)]
mod tests {
    use core::str;
    use rand_core::OsRng;

    use super::DecryptIdentity;
    use super::EncryptIdentity;
    use super::PrivateIdentity;

    #[test]
    fn encrypt_then_decrypt() {
        let private_identity = PrivateIdentity::new_from_rand(OsRng);
        let out_message = "#--TEST-MESSAGE--#";
        let mut out_buf = [0u8; 4096];
        let mut in_buf = [0u8; 4096];

        let cipher_message = private_identity
            .identity
            .encrypt(OsRng, out_message.as_bytes(), &mut out_buf)
            .expect("encrypted message");

        let in_message = str::from_utf8(
            private_identity
                .decrypt(OsRng, cipher_message, &mut in_buf)
                .expect("decrypted message"),
        )
        .expect("valid string");

        assert_eq!(in_message, out_message);
    }
}
