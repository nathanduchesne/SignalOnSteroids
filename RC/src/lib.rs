use std::{collections::HashMap};

use rand_core::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use hex_literal::hex;
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroize;


const MAX_SKIP: usize = 100;

pub use cipher;

/// Using the curve25519-dalek generator.
#[derive(Clone)]
pub struct DiffieHellmanParameters {
    pub secret: StaticSecret,
    pub public: PublicKey
}


pub fn init_all() -> (State, State) {
    let alice_shared_secret_params = generate_dh();
    let bob_shared_secret_params = generate_dh();
    let shared_secret = dh(alice_shared_secret_params, bob_shared_secret_params.public);

    // Signal algorithm states: " To allow Bob to send messages immediately after initialization Bob's sending chain key 
    // and Alice's receiving chain key could be initialized to a shared secret."
    let alice_shared_ratchet_params = generate_dh();
    let bob_shared_ratchet_params = generate_dh();
    let ratchet_shared_secret = dh(alice_shared_ratchet_params, bob_shared_ratchet_params.public);

    let bob_ratchet_dh_params = generate_dh();
    
    let alice_state = ratchet_init_alice(&shared_secret, &bob_ratchet_dh_params.public, &ratchet_shared_secret);
    let bob_state = ratchet_init_bob(&shared_secret, bob_ratchet_dh_params, &ratchet_shared_secret);
    return (alice_state, bob_state)


}

pub fn dh(user_dh_params: DiffieHellmanParameters, other_user_public: PublicKey) -> SharedSecret {
    return user_dh_params.secret.diffie_hellman(&other_user_public);
}

pub fn generate_dh() -> DiffieHellmanParameters {
    let user_secret = StaticSecret::new(OsRng);
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
    let ciphertext = Aes256CbcEnc::new(&encryption_key.into(), &iv.into())
    .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    

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

    let ciphertext_without_hmac = ciphertext[..ciphertext.len() - 32].to_vec();
    let plaintext = Aes256CbcDec::new(&decryption_key.into(), &iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext_without_hmac)
    .unwrap();

    return Ok(plaintext.to_vec());
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub dh_ratchet_key: PublicKey, 
    pub prev_chain_len: usize,
    pub msg_nbr: usize,
    pub epoch: usize
}

/// Syntactic sugar to match the Signal Double Ratchet Algorithm API
pub fn header(dh_pair: PublicKey, pn: usize, n: usize, epoch: usize) -> Header {
    Header { dh_ratchet_key: dh_pair, prev_chain_len: pn, msg_nbr: n, epoch: epoch }
}

pub fn concat(ad: &[u8], header: Header) -> Vec<u8> {
    let len_ad = ad.len();
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(&len_ad.to_be_bytes());
    result.extend_from_slice(ad);

    result.extend_from_slice(header.dh_ratchet_key.as_bytes());
    result.extend_from_slice(&header.prev_chain_len.to_be_bytes());
    result.extend_from_slice(&header.msg_nbr.to_be_bytes());
    return result;
}

#[allow(non_snake_case)]
pub struct State {
    pub DHs: DiffieHellmanParameters,
    pub DHr: PublicKey,
    pub RK: RootKey,
    pub CKs: ChainKey,
    pub CKr: ChainKey,
    pub Ns: usize,
    pub Nr: usize,
    pub PN: usize,
    pub MKSKIPPED: HashMap<(PublicKey, usize), MessageKey>,
    pub epoch: usize
}

#[allow(non_snake_case)]
pub fn ratchet_init_alice(SK: &SharedSecret, bob_dh_public_key: &PublicKey, ratchet_shared_secret: &SharedSecret) -> State {
    let dh_pair = generate_dh();
    let (root_key, chain_key) = kdf_rk(SK.as_bytes(), dh(dh_pair.clone(), *bob_dh_public_key));
    State { 
         DHs: dh_pair,
         DHr: bob_dh_public_key.clone(), 
         RK: root_key, 
         CKs: chain_key, 
         CKr: ratchet_shared_secret.to_bytes(), 
         Ns: 0, 
         Nr: 0, 
         PN: 0, 
         MKSKIPPED: HashMap::new(),
         epoch: 0
        }
}

#[allow(non_snake_case)]
pub fn ratchet_init_bob(SK: &SharedSecret, bob_dh_key_pair: DiffieHellmanParameters, ratchet_shared_secret: &SharedSecret) -> State {
    let filling_value = generate_dh().public;
    State { 
         DHs: bob_dh_key_pair,
         DHr: filling_value, 
         RK: SK.to_bytes(), 
         CKs: ratchet_shared_secret.to_bytes(), 
         CKr: [0; 32], 
         Ns: 0, 
         Nr: 0, 
         PN: 0, 
         MKSKIPPED: HashMap::new(),
         epoch: 0
        }
}


pub fn ratchet_encrypt(state: &mut State, plaintext: &[u8], associated_data: &[u8]) -> (Header, Vec<u8>) {
    let mk: MessageKey;
    (state.CKs, mk) = kdf_ck(&state.CKs);
    let header = header(state.DHs.public, state.PN, state.Ns, state.epoch);
    state.Ns += 1;
    return (header, encrypt(&mk, plaintext, associated_data));
}
pub fn try_skipped_message_keys(state: &mut State, header: &Header, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if state.MKSKIPPED.contains_key(&(header.dh_ratchet_key, header.msg_nbr)) {
        let mk = state.MKSKIPPED.remove(&(header.dh_ratchet_key, header.msg_nbr)).unwrap();
        return decrypt(&mk, ciphertext, associated_data);
    }
    else {
        return Err("Not in skipped messages.");
    }
}

pub fn skip_message_keys(state: &mut State, until: usize) -> Result<usize, &'static str>{
    if state.Nr + MAX_SKIP < until {
        return Err("No such message exists.");
    }
    // Initial state of receiving chain key before receiving first DH ratchet PK.
    if state.CKr != [0;32] {
        while state.Nr < until {
            let mk: MessageKey;
            (state.CKr, mk) = kdf_ck(&state.CKr);
            state.MKSKIPPED.insert((state.DHr, state.Nr), mk);
            state.Nr += 1;
        }
    }
    return Ok(1);
}

pub fn dh_ratchet(state: &mut State, header: &Header) -> () {
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.dh_ratchet_key;
    (state.RK, state.CKr) = kdf_rk(&state.RK, dh(state.DHs.clone(), state.DHr));
    // Clean memory from any secret keys
    state.DHs.secret.zeroize();
    state.DHs = generate_dh();
    (state.RK, state.CKs) = kdf_rk(&state.RK, dh(state.DHs.clone(), state.DHr));
    state.epoch += 1;

}


pub fn ratchet_decrypt(state: &mut State, header: Header, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let plaintext = try_skipped_message_keys(state, &header, ciphertext, associated_data);
    match plaintext {
        Ok(_) => return plaintext,
        Err("HMAC does not match, authentication failed.") => return Err("HMAC does not match, authentication failed."),
        _ => {
            if header.dh_ratchet_key != state.DHr {
                match skip_message_keys(state, header.prev_chain_len) {
                    Err(_) => return Err("No such message exists."),
                    Ok(_) => {
                        dh_ratchet(state, &header);
                        match skip_message_keys(state, header.msg_nbr) {
                            Err(_) => return Err("No such message exists."),
                            Ok(_) => {
                                let mk: MessageKey;
                                (state.CKr, mk) = kdf_ck(&state.CKr);
                                state.Nr += 1;
                                return decrypt(&mk, ciphertext, associated_data);
                            }
                        }
                        
                    }
                }
            }
            else {
                match skip_message_keys(state, header.msg_nbr) {
                    Err(_) => return Err("No such message exists."),
                    Ok(_) => {
                        let mk: MessageKey;
                        (state.CKr, mk) = kdf_ck(&state.CKr);
                        state.Nr += 1;
                        return decrypt(&mk, ciphertext, associated_data);
                    }
                }
            }
        },
    }
}

pub struct Ordinal {
    pub epoch: usize,
    pub index: usize
}

pub fn send(state: &mut State, associated_data: &[u8], plaintext: &[u8]) -> (Ordinal, Header, Vec<u8>) {
    let (header, ciphertext) = ratchet_encrypt(state, plaintext, associated_data);
    return (Ordinal{epoch: state.epoch, index: header.msg_nbr}, header, ciphertext)
}

pub fn receive(state: &mut State, associated_data: &[u8], header: Header, ciphertext: &[u8]) -> (bool, Ordinal, Vec<u8>) {
    let decryption_result = ratchet_decrypt(state, header, ciphertext, associated_data);
    match decryption_result {
        Ok(val) => (true, Ordinal{epoch: header.epoch, index: header.msg_nbr}, val),
        Err(_) => (false, Ordinal{epoch: 0, index: 0}, Vec::new())
    }
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
    //TODO: 
    // 2) test that when HMAC check fails
    // 3) test that when ratchet PK changes, we can decyrpt previous skipped msgs

    #[test]
    fn ratchet_works_when_alice_sends_multiple_messages_with_no_response_from_bob() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let alice_plaintext = *b"Hello Bob! I am Alice.";
        let mut associated_data: [u8; 44] = [17; 44];
        let alice_first_message_sent = ratchet_encrypt(&mut alice_state, &alice_plaintext, &associated_data);

        let bob_first_message_received = ratchet_decrypt(&mut bob_state, alice_first_message_sent.0, &alice_first_message_sent.1, &associated_data);
        assert_eq!(bob_first_message_received.unwrap(), alice_plaintext);

        let alice_second_plaintext = *b"Can you understand me?";
        associated_data = [21; 44];
        let alice_second_message_sent = ratchet_encrypt(&mut alice_state, &alice_second_plaintext, &associated_data);

        let bob_second_message_received = ratchet_decrypt(&mut bob_state, alice_second_message_sent.0, &alice_second_message_sent.1, &associated_data);
        assert_eq!(bob_second_message_received.unwrap(), alice_second_plaintext);
    }

    #[test]
    fn ratchet_works_when_both_parties_communicate_no_reordering() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let alice_plaintext = *b"Hello Bob! I am Alice.";
        let mut associated_data: [u8; 44] = [17; 44];
        let alice_first_message_sent = ratchet_encrypt(&mut alice_state, &alice_plaintext, &associated_data);

        let bob_first_message_received = ratchet_decrypt(&mut bob_state, alice_first_message_sent.0, &alice_first_message_sent.1, &associated_data);
        assert_eq!(bob_first_message_received.unwrap(), alice_plaintext);

        associated_data = [100; 44];
        let bob_plaintext = *b"Hello Alice, I am Bob and hear you!";
        let bob_first_message_sent = ratchet_encrypt(&mut bob_state, &bob_plaintext, &associated_data);

        let alice_first_message_received = ratchet_decrypt(&mut alice_state, bob_first_message_sent.0, &bob_first_message_sent.1, &associated_data);
        assert_eq!(alice_first_message_received.unwrap(), bob_plaintext);

        let a2 = *b"Cool!";
        let a3 = *b"How are you?";
        let c_a2 = ratchet_encrypt(&mut alice_state, &a2, &associated_data);
        let c_a3 = ratchet_encrypt(&mut alice_state, &a3, &associated_data);

        assert_eq!(ratchet_decrypt(&mut bob_state, c_a2.0, &c_a2.1, &associated_data).unwrap(), a2);
        assert_eq!(ratchet_decrypt(&mut bob_state, c_a3.0, &c_a3.1, &associated_data).unwrap(), a3);

        let b2 = *b"Looking good";
        let c_b2 = ratchet_encrypt(&mut bob_state, &b2, &associated_data);
        assert_eq!(ratchet_decrypt(&mut alice_state, c_b2.0, &c_b2.1, &associated_data).unwrap(), b2);

    }

    #[test]
    fn ratchet_works_with_reordering() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let alice_plaintext = *b"Hello Bob! I am Alice.";
        let associated_data: [u8; 44] = [17; 44];
        let c_a1 = ratchet_encrypt(&mut alice_state, &alice_plaintext, &associated_data);
        let a2 = *b"You hear me?";
        let c_a2 = ratchet_encrypt(&mut alice_state, &a2, &associated_data);

        assert_eq!(ratchet_decrypt(&mut bob_state, c_a2.0, &c_a2.1, &associated_data).unwrap(), a2);
        
        let b1 = *b"I hear you but haven't gotten your first message yet";
        let c_b1 = ratchet_encrypt(&mut bob_state, &b1, &associated_data);
        assert_eq!(ratchet_decrypt(&mut alice_state, c_b1.0, &c_b1.1, &associated_data).unwrap(), b1);

        let a3 = *b"The postman is stuck in traffic :)";
        let c_a3 = ratchet_encrypt(&mut alice_state, &a3, &associated_data);
        assert_eq!(ratchet_decrypt(&mut bob_state, c_a3.0, &c_a3.1, &associated_data).unwrap(), a3);

        assert_eq!(ratchet_decrypt(&mut bob_state, c_a1.0, &c_a1.1, &associated_data).unwrap(), alice_plaintext);
    }

    #[test]
    fn ratchet_fails_when_hmac_check_fails() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let alice_plaintext = *b"Hello Bob! I am Alice.";
        let associated_data: [u8; 44] = [17; 44];
        let c_a1 = ratchet_encrypt(&mut alice_state, &alice_plaintext, &associated_data);
        assert_eq!(ratchet_decrypt(&mut bob_state, Header{dh_ratchet_key: c_a1.0.dh_ratchet_key, prev_chain_len: c_a1.0.prev_chain_len, msg_nbr: c_a1.0.msg_nbr + 1, epoch: 0}, &c_a1.1, &associated_data), Err("HMAC does not match, authentication failed."));
    }

    #[test]
    fn ratchet_fails_when_msg_nbr_is_too_high() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let alice_plaintext = *b"Hello Bob! I am Alice.";
        let associated_data: [u8; 44] = [17; 44];
        let c_a1 = ratchet_encrypt(&mut alice_state, &alice_plaintext, &associated_data);
        assert_eq!(ratchet_decrypt(&mut bob_state, Header{dh_ratchet_key: c_a1.0.dh_ratchet_key, prev_chain_len: c_a1.0.prev_chain_len, msg_nbr: c_a1.0.msg_nbr + 1 + MAX_SKIP, epoch: 0}, &c_a1.1, &associated_data), Err("No such message exists."));
    }

    #[test]
    fn ratchet_succeeds_when_bob_starts_communication() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let bob_msg = *b"What if I start?";
        let associated_data: [u8; 44] = [17; 44];
        let bob_ciphertext = ratchet_encrypt(&mut bob_state, &bob_msg, &associated_data);
        assert_eq!(ratchet_decrypt(&mut alice_state, bob_ciphertext.0, &bob_ciphertext.1, &associated_data).unwrap(), bob_msg);
    }

    #[test]
    fn ratchet_succeeds_with_arbitrary_length_msg_using_dynamic_alloc() {
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = init_all();

        let bob_msg = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi porttitor neque at euismod dapibus. Pellentesque aliquet auctor dolor. Vivamus venenatis leo a purus dictum, eget rhoncus orci scelerisque. Maecenas ultricies ipsum ac est posuere, et dapibus eros interdum. Vestibulum lacinia id purus et vulputate. Nam commodo purus ut tempus dapibus. Curabitur in hendrerit ex. Donec consectetur justo eu tortor molestie imperdiet. Fusce dapibus mollis orci id interdum. Mauris ac scelerisque augue, eu malesuada velit. Ut quis massa dolor.";
        let associated_data: [u8; 44] = [17; 44];
        let bob_ciphertext = ratchet_encrypt(&mut bob_state, &bob_msg, &associated_data);
        assert_eq!(ratchet_decrypt(&mut alice_state, bob_ciphertext.0, &bob_ciphertext.1, &associated_data).unwrap(), bob_msg);
    }


    #[test]
    fn it_works() {
        let result = 2+2;
        assert_eq!(result, 4);
    }
}
