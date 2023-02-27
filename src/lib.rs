use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hex_literal::hex;
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};


const BLOCK_SIZE: usize = 48;

pub use cipher;

/// Using the curve25519-dalek generator.
pub struct DiffieHellmanParameters {
    pub secret: EphemeralSecret,
    pub public: PublicKey
}

pub fn dh(user_dh_params: DiffieHellmanParameters, other_user_public: PublicKey) -> SharedSecret {
    return user_dh_params.secret.diffie_hellman(&other_user_public);
}

pub fn generate_dh() -> DiffieHellmanParameters {
    let user_secret = EphemeralSecret::new(OsRng);
    let user_public = PublicKey::from(&user_secret);
    DiffieHellmanParameters { secret: user_secret, public: user_public}
}


type RootKey    = [u8; 32];
type ChainKey   = [u8; 32];
type MessageKey = [u8; 32];
/// This function is recommended to be implemented using HKDF with SHA-256 or SHA-512
/// using rk as HKDF salt, dh_out as HKDF input key material, and an application-specific 
/// byte sequence as HKDF info. The info value should be chosen to be distinct from other 
/// uses of HKDF in the application.
pub fn kdf_rk(rk: &[u8; 32], dh_out: SharedSecret) -> (RootKey, ChainKey) {
    let ikm = dh_out.as_bytes();
    let salt = rk;
    let info = hex!("734f73666f724550464c"); // 'sOsforEPFL'

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm)
        .expect("64 is a valid length for Sha256 to output");
    let mut root_key = [0u8; 32];
    root_key.clone_from_slice(&okm[0..32]);
    let mut chain_key = [0u8; 32];
    chain_key.clone_from_slice(&okm[32..64]);
    return (root_key, chain_key);
}

type HmacSha256 = Hmac<Sha256>;
pub fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let mut mac_msg = HmacSha256::new_from_slice(ck)
    .expect("HMAC can take key of any size");
    mac_msg.update(b"01");

    let result_msg: [u8; 32] = mac_msg.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");

    let mut mac_chain = HmacSha256::new_from_slice(ck)
    .expect("HMAC can take key of any size");
    mac_chain.update(b"02");
    let result_chain: [u8; 32] = mac_chain.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");
    return (result_chain, result_msg)
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
pub fn encrypt(mk: &MessageKey, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let ikm = mk;
    let salt: [u8; 32] = [0; 32];
    let info = hex!("734f73456e6372797074"); // 'sOsEncrypt'

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm);
    let mut okm = [0u8; 80];
    hk.expand(&info, &mut okm)
        .expect("80 is a valid length for Sha256 to output");

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&okm[0..32]);

    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&okm[32..64]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&okm[64..80]);

    //let ciphertext = Aes256CbcEnc::new(&encryption_key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    //let ciphertext: [u8; 32] = [0; 32];
    let mut buf = [0u8; 48];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(&plaintext);
    let ciphertext = Aes256CbcEnc::new(&encryption_key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    

    // HMAC is calculated using the authentication key and the same hash function as above [2]. The HMAC input is the associated_data prepended to the ciphertext. 
    // The HMAC output is appended to the ciphertext.
    let mut hmac = HmacSha256::new_from_slice(&auth_key)
    .expect("HMAC can take key of any size");
    let mut hmac_input: Vec<u8> = associated_data.to_vec();
    hmac_input.extend_from_slice(&ciphertext);
    hmac.update(&hmac_input);

    let hmac_output: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");

    let mut ciphertext_with_hmac = ciphertext.to_vec();
    ciphertext_with_hmac.extend_from_slice(&hmac_output);

    return ciphertext_with_hmac;
}

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
pub fn decrypt(mk: &MessageKey, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let ikm = mk;
    let salt: [u8; 32] = [0; 32];
    let info = hex!("734f73456e6372797074"); // 'sOsEncrypt'

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm);
    let mut okm = [0u8; 80];
    hk.expand(&info, &mut okm)
        .expect("80 is a valid length for Sha256 to output");

    let mut decryption_key = [0u8; 32];
    decryption_key.copy_from_slice(&okm[0..32]);

    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&okm[32..64]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&okm[64..80]);


    let mut hmac = HmacSha256::new_from_slice(&auth_key)
    .expect("HMAC can take key of any size");
    let mut hmac_input: Vec<u8> = associated_data.to_vec();
    hmac_input.extend_from_slice(&ciphertext[..ciphertext.len() - 32]);
    hmac.update(&hmac_input);

    let hmac_output: [u8; 32] = hmac.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");
    // Check if HMAC matches the one in the ciphertext.
    if hmac_output != ciphertext[ciphertext.len() - 32..ciphertext.len()] {
        return Err("HMAC does not match, authentication failed.")
    }

    let mut ciphertext_without_hmac = ciphertext[..ciphertext.len() - 32].to_vec();
    let plaintext = Aes256CbcDec::new(&decryption_key.into(), &iv.into())
    .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_without_hmac)
    .unwrap();

    return Ok(plaintext.to_vec());
}

pub struct Header {
    pub dh_ratchet_key: PublicKey, 
    pub rev_chain_len: usize,
    pub msg_nbr: usize
}

/// Syntactic sugar to match the Signal Double Ratchet Algorithm API
pub fn header(dh_pair: PublicKey, pn: usize, n: usize) -> Header {
    Header { dh_ratchet_key: dh_pair, rev_chain_len: pn, msg_nbr: n }
}

pub fn concat(ad: &[u8], header: Header) -> Vec<u8> {
    let len_ad = ad.len();
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(&len_ad.to_be_bytes());
    result.extend_from_slice(ad);

    result.extend_from_slice(header.dh_ratchet_key.as_bytes());
    result.extend_from_slice(&header.rev_chain_len.to_be_bytes());
    result.extend_from_slice(&header.msg_nbr.to_be_bytes());
    return result;
}






#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_works() {
        let alice_dh = generate_dh();
        let bob_dh = generate_dh();

        let alice_pk_copy = alice_dh.public.clone();
        let alice_shared_secret = dh(alice_dh, bob_dh.public);
        let bob_shared_secret = dh(bob_dh, alice_pk_copy);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }

    #[test]
    fn shared_secret_with_non_matching_secrets_fails() {
        let alice_dh = generate_dh();
        let bob_dh = generate_dh();
    
        let alice_shared_secret = dh(alice_dh, bob_dh.public);
        let fake = generate_dh();
        let bob_shared_secret = dh(bob_dh, fake.public);
        assert_ne!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes()); 
    }    

    #[test]
    fn encrypt_and_decrypt_is_correct() {
        let key: [u8; 32] = [0;32];
        let plaintext = *b"hello world! this is my plaintext.";
        let associated_data: [u8; 44] = [2; 44];

        let ciphertext = encrypt(&key, &plaintext, &associated_data);
        let decrypted_ciphertext = decrypt(&key, &ciphertext, &associated_data);

        assert_eq!(decrypted_ciphertext.unwrap(), plaintext);
    }

    #[test]
    /// https://github.com/pyca/cryptography/blob/main/vectors/cryptography_vectors/KDF/rfc-5869-HKDF-SHA256.txt
    fn kdf_rk_works() {
        let ikm = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = hex!("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); // 'sOsforEPFL'
    
        let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
        let mut okm = [0u8; 82];
        hk.expand(&info, &mut okm)
            .expect("82 is a valid length for Sha256 to output");
        let mut root_key = [0u8; 32];
        root_key.clone_from_slice(&okm[0..32]);
        let mut chain_key = [0u8; 32];
        chain_key.clone_from_slice(&okm[32..64]);
        let root_key_verif = hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c");
        assert_eq!(root_key, root_key_verif);
        let chain_key_verif = hex!("59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71");
        assert_eq!(chain_key, chain_key_verif);
    }

    #[test]
    fn encrypt_and_decrypt_fails_on_incorrect_pt_ct_pair() {
        let key: [u8; 32] = [0;32];
        let plaintext = *b"hello world! this is my plaintext.";
        let associated_data: [u8; 44] = [2; 44];

        let ciphertext = encrypt(&key, &plaintext, &associated_data);
        let decrypted_ciphertext = decrypt(&key, &ciphertext, &associated_data);

        let plaintext = *b"hello world! this is my klaintext.";
        assert_ne!(decrypted_ciphertext.unwrap(), plaintext);
    }

    #[test]
    fn decrypt_fails_if_hmac_incorrect() {
        let key: [u8; 32] = [0;32];
        let plaintext = *b"hello world! this is my plaintext.";
        let associated_data: [u8; 44] = [2; 44];

        let mut ciphertext = encrypt(&key, &plaintext, &associated_data);
        let last_byte_hmac = ciphertext.pop().unwrap();
        ciphertext.push(last_byte_hmac + 1);
        let decrypted_ciphertext = decrypt(&key, &ciphertext, &associated_data);

        assert_eq!(decrypted_ciphertext, Err("HMAC does not match, authentication failed."));
    }

    #[test]
    fn it_works() {
        let result = 2+2;
        assert_eq!(result, 4);
    }
}
