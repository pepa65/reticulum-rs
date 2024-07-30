use core::mem::size_of;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockDecryptMut;
use aes::cipher::Iv;
use aes::cipher::Key;
use aes::cipher::Unsigned;
use cbc::cipher::BlockEncryptMut;
use cbc::cipher::KeyIvInit;
use crypto_common::KeyInit;
use crypto_common::KeySizeUser;
use hmac::Mac;
use rand_core::CryptoRngCore;
use sha2::Sha256;

use crate::error::RnsError;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = hmac::Hmac<Sha256>;

const HMAC_KEY_SIZE: usize = <<HmacSha256 as KeySizeUser>::KeySize as Unsigned>::USIZE;
const AES_KEY_SIZE: usize = <<aes::Aes128 as KeySizeUser>::KeySize as Unsigned>::USIZE;

pub struct Fernet<R: CryptoRngCore> {
    rng: R,
    sign_key: Key<HmacSha256>,
    enc_key: Key<aes::Aes128>,
}

impl<R: CryptoRngCore> Fernet<R> {
    pub fn new(sign_key: Key<HmacSha256>, enc_key: Key<aes::Aes128>, rng: R) -> Self {
        Self {
            rng,
            sign_key,
            enc_key,
        }
    }

    pub fn new_from_slices(
        sign_key: [u8; HMAC_KEY_SIZE],
        enc_key: [u8; AES_KEY_SIZE],
        rng: R,
    ) -> Self {
        Self {
            rng,
            sign_key: sign_key.into(),
            enc_key: enc_key.into(),
        }
    }

    pub fn new_rand(mut rng: R) -> Self {
        let sign_key = HmacSha256::generate_key(&mut rng);
        let enc_key = Aes128CbcEnc::generate_key(&mut rng);

        Self {
            rng,
            sign_key,
            enc_key,
        }
    }

    pub fn encrypt<'a>(
        &mut self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], RnsError> {
        // Generate random IV
        let iv = Aes128CbcEnc::generate_iv(&mut self.rng);

        let mut out_len = 0;

        if out_buf.len() < (out_len + iv.len()) {
            return Err(RnsError::InvalidArgument);
        }

        out_buf[..iv.len()].copy_from_slice(iv.as_slice());

        out_len += iv.len();

        let chiper_len = Aes128CbcEnc::new(&self.enc_key, &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(msg, &mut out_buf[out_len..])
            .unwrap()
            .len();

        out_len += chiper_len;

        let mut mac = <HmacSha256 as KeyInit>::new(&self.sign_key);
        mac.update(&out_buf[..out_len]);

        let tag = mac.finalize().into_bytes();
        out_buf[out_len..out_len + tag.len()].copy_from_slice(tag.as_slice());

        Ok(&mut out_buf[..out_len])
    }

    pub fn verify(&mut self, msg: &[u8]) -> Result<(), RnsError> {
        if msg.len() <= HMAC_KEY_SIZE {
            return Err(RnsError::InvalidArgument);
        }

        let mut mac = <HmacSha256 as KeyInit>::new(&self.sign_key);
        mac.update(&msg[..]);

        let tag = mac.finalize().into_bytes();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::crypt::fernet::Fernet;

    #[test]
    fn encrypt_then_decrypt() {
        let mut fernet = Fernet::new_rand(OsRng);

        let msg = "#FERNET_TEST_MESSAGE#";
        let mut out_buf = [0u8; 4096];

        fernet.encrypt(msg.as_bytes(), &mut out_buf[..4096]);
    }
}
