use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hex_literal::hex;
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};

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

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result_msg: [u8; 32] = mac_msg.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");

    let mut mac_chain = HmacSha256::new_from_slice(ck)
    .expect("HMAC can take key of any size");
    mac_chain.update(b"02");
    let result_chain: [u8; 32] = mac_chain.finalize().into_bytes().as_slice().try_into().expect("Length should be 32 bytes.");
    return (result_chain, result_msg)
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
    fn it_works() {
        let result = 2+2;
        assert_eq!(result, 4);
    }
}
