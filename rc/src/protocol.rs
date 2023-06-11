use std::{collections::HashMap};

use rand_core::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use hex_literal::hex;
use sha2::Sha256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroize;
use bytevec::{ByteEncodable, ByteDecodable, BVSize, BVEncodeResult, BVDecodeResult};
use std::mem::size_of;



pub(crate) const MAX_SKIP: usize = 100;

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
fn kdf_rk(rk: &[u8; 32], dh_out: SharedSecret) -> (RootKey, ChainKey) {
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
fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
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
pub(crate) fn encrypt(mk: &MessageKey, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
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
pub(crate) fn decrypt(mk: &MessageKey, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
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
fn header(dh_pair: PublicKey, pn: usize, n: usize, epoch: usize) -> Header {
    Header { dh_ratchet_key: dh_pair, prev_chain_len: pn, msg_nbr: n, epoch: epoch }
}

fn concat(ad: &[u8], header: Header) -> Vec<u8> {
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
#[derive(Clone)]
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
fn ratchet_init_alice(SK: &SharedSecret, bob_dh_public_key: &PublicKey, ratchet_shared_secret: &SharedSecret) -> State {
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
fn ratchet_init_bob(SK: &SharedSecret, bob_dh_key_pair: DiffieHellmanParameters, ratchet_shared_secret: &SharedSecret) -> State {
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


pub(crate) fn ratchet_encrypt(state: &mut State, plaintext: &[u8], associated_data: &[u8]) -> (Header, Vec<u8>) {
    let mk: MessageKey;
    (state.CKs, mk) = kdf_ck(&state.CKs);
    let header = header(state.DHs.public, state.PN, state.Ns, state.epoch);
    state.Ns += 1;
    return (header, encrypt(&mk, plaintext, &concat(associated_data, header)));
}
fn try_skipped_message_keys(state: &mut State, header: &Header, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if state.MKSKIPPED.contains_key(&(header.dh_ratchet_key, header.msg_nbr)) {
        let mk = state.MKSKIPPED.remove(&(header.dh_ratchet_key, header.msg_nbr)).unwrap();
        return decrypt(&mk, ciphertext, &concat(associated_data, *header));
    }
    else {
        return Err("Not in skipped messages.");
    }
}

fn skip_message_keys(state: &mut State, until: usize) -> Result<usize, &'static str>{
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

fn dh_ratchet(state: &mut State, header: &Header) -> () {
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


pub(crate) fn ratchet_decrypt(state: &mut State, header: Header, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, &'static str> {
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
                                return decrypt(&mk, ciphertext, &concat(associated_data, header));
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
                        return decrypt(&mk, ciphertext, &concat(associated_data, header));
                    }
                }
            }
        },
    }
}
#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Ordinal {
    pub epoch: usize,
    pub index: usize
}

impl ByteEncodable for Ordinal {
    /// Returns the total length of the byte buffer that is obtained through encode() 
    fn get_size<Size>(&self) -> Option<Size> where Size: BVSize + ByteEncodable {
        let usize_for_env = size_of::<usize>();
        return Some(BVSize::from_usize(2 * usize_for_env));
    }
    /// Returns a byte representation of the original data object
    fn encode<Size>(&self) -> BVEncodeResult<Vec<u8>> where Size: BVSize + ByteEncodable {
        let mut bytes = [0u8; 2 * size_of::<usize>()];
        bytes[0..size_of::<usize>()].clone_from_slice(&self.epoch.to_be_bytes());
        bytes[size_of::<usize>()..2*size_of::<usize>()].copy_from_slice(&self.index.to_be_bytes());

        return Ok(bytes.to_vec());
    }
}

impl ByteDecodable for Ordinal {
    /// Returns an instance of `Self` obtained from the deserialization of the provided byte buffer.
    fn decode<Size>(bytes: &[u8]) -> BVDecodeResult<Self> where Size: BVSize + ByteDecodable {
        let ordinal_epoch = usize::from_be_bytes(bytes[0..size_of::<usize>()].try_into().unwrap());
        let ordinal_index = usize::from_be_bytes(bytes[size_of::<usize>()..2*size_of::<usize>()].try_into().unwrap());

        return Ok(Ordinal { epoch: ordinal_epoch, index: ordinal_index });
    }
}


pub fn send(state: &mut State, associated_data: &[u8], plaintext: &[u8]) -> (Ordinal, Header, Vec<u8>) {
    let (header, ciphertext) = ratchet_encrypt(state, plaintext, associated_data);
    return (Ordinal{epoch: header.epoch, index: header.msg_nbr}, header, ciphertext)
}

pub fn receive(state: &mut State, associated_data: &[u8], header: Header, ciphertext: &[u8]) -> (bool, Ordinal, Vec<u8>) {
    let decryption_result = ratchet_decrypt(state, header, ciphertext, associated_data);
    match decryption_result {
        Ok(val) => (true, Ordinal{epoch: header.epoch, index: header.msg_nbr}, val),
        Err(_) => return (false, Ordinal{epoch: 0, index: 0}, Vec::new())
    }
}

