extern crate rc; 
use std::collections::{BinaryHeap, BTreeSet};
use std::hash::{Hash, self};
use std::mem::size_of;
use std::sync::MutexGuard;
use std::{collections::HashSet, num};
use std::cmp::Ordering;
use digest::generic_array::GenericArray;
use hex_literal::hex;
use mset_mu_hash::RistrettoHash;
use sha2::{Sha256, Sha512, Digest};
use blake2::{Blake2s256};
use std::time::{SystemTime};
use std::fs::{File};
use std::io::prelude::*;
use rand::{RngCore, CryptoRng};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rc::{State, Ordinal, Header, init_all, generate_dh, dh, send, receive};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use bytevec::{ByteEncodable, ByteDecodable, BVSize, BVEncodeResult, BVDecodeResult};


#[derive(Clone)]
pub struct RrcState {
    pub state: State,
    pub hash_key: [u8;32],
    pub hash_key_prime: [u8;32], 
    pub S: HashSet<Message>,
    pub R: HashSet<Message>,
    pub S_ack: HashSet<Message>,
    pub max_num: Ordinal,
    pub security_level: Security
}



#[derive(Clone)]
pub struct OptimizedSendRrcState {
    pub state: RrcState,
    pub incremental_hash: [u8; 32 + 2 * m_bytes],
    pub hash_S: RistrettoHash<Sha512>,
    pub hash_ordinal_set: RistrettoHash<Sha512>,
    pub nums_prime: HashSet<Ordinal>,
}

pub fn rrc_init_all(security_level: Security) -> (RrcState, RrcState) {
    // do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();

    let hash_key = dh(alice_hash_key, bob_hash_key.public);
    let hash_key_prime = dh(alice_hash_key_prime, bob_hash_key_prime.public);
    let (mut alice_rc_state, mut bob_rc_state) = init_all();
    let mut alice_state = RrcState{state: alice_rc_state, hash_key: hash_key.to_bytes().clone(), hash_key_prime: hash_key_prime.to_bytes().clone(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: Ordinal { epoch: 0, index: 0 }, security_level: security_level.clone()};
    let mut bob_state = RrcState{state: bob_rc_state, hash_key: hash_key.to_bytes(), hash_key_prime: hash_key_prime.to_bytes(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: Ordinal { epoch: 0, index: 0 }, security_level: security_level};

    return (alice_state, bob_state);
}

pub fn rrc_init_all_optimized_send(security_level: Security) -> (OptimizedSendRrcState, OptimizedSendRrcState) {
    // do key exchange for both hash keys
    let (mut rrc_alice, mut rrc_bob) = rrc_init_all(security_level);
    
    let alice_initial_hash = incremental_hash_fct_of_whole_set(&rrc_alice.R, &rrc_alice.hash_key_prime.clone());
    let bob_initial_hash = incremental_hash_fct_of_whole_set(&rrc_bob.R, &rrc_bob.hash_key_prime.clone());
    return (OptimizedSendRrcState{state: rrc_alice, incremental_hash: alice_initial_hash, hash_S: RistrettoHash::<Sha512>::default(), hash_ordinal_set: RistrettoHash::<Sha512>::default(), nums_prime: HashSet::new()},
            OptimizedSendRrcState{state: rrc_bob, incremental_hash: bob_initial_hash, hash_S: RistrettoHash::<Sha512>::default(), hash_ordinal_set: RistrettoHash::<Sha512>::default(), nums_prime: HashSet::new()});
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Ord, PartialOrd)]
pub struct Message {
    pub ordinal: Ordinal,
    pub content: [u8;32]
}


impl ByteEncodable for Message {
    /// Returns the total length of the byte buffer that is obtained through encode() 
    fn get_size<Size>(&self) -> Option<Size> where Size: BVSize + ByteEncodable {
        let usize_for_env = size_of::<usize>();
        return Some(BVSize::from_usize(32 + 2 * usize_for_env));
    }
    /// Returns a byte representation of the original data object
    fn encode<Size>(&self) -> BVEncodeResult<Vec<u8>> where Size: BVSize + ByteEncodable {
        let mut bytes = [0u8; 32 + 2 * size_of::<usize>()];
        bytes[0..size_of::<usize>()].clone_from_slice(&self.ordinal.epoch.to_be_bytes());
        bytes[size_of::<usize>()..2*size_of::<usize>()].copy_from_slice(&self.ordinal.index.to_be_bytes());
        bytes[2*size_of::<usize>()..2*size_of::<usize>() + 32].copy_from_slice(&self.content);

        return Ok(bytes.to_vec());
    }
}

impl ByteDecodable for Message {
    /// Returns an instance of `Self` obtained from the deserialization of the provided byte buffer.
    fn decode<Size>(bytes: &[u8]) -> BVDecodeResult<Self> where Size: BVSize + ByteDecodable {
        let ordinal_epoch = usize::from_be_bytes(bytes[0..size_of::<usize>()].try_into().unwrap());
        let ordinal_index = usize::from_be_bytes(bytes[size_of::<usize>()..2*size_of::<usize>()].try_into().unwrap());
        let content: [u8; 32] = bytes[2*size_of::<usize>()..2*size_of::<usize>() + 32].try_into().unwrap();

        return Ok(Message{ordinal:Ordinal { epoch: ordinal_epoch, index: ordinal_index }, content: content.try_into().unwrap()});
    }
}




#[derive(Clone)]
pub struct Ciphertext {
    pub ciphertext: Vec<u8>,
    pub S: HashSet<Message>,
    pub R: (HashSet<Ordinal>, [u8;32])
}

#[derive(Clone)]
pub struct OptimizedSendCiphertext {
    pub ciphertext: Vec<u8>,
    pub S: HashSet<Message>,
    pub R: (HashSet<Ordinal>, [u8;32 + 2 * m_bytes])
}

fn get_hash_msg_set(R: &HashSet<Message>, hash_key_prime: [u8; 32]) -> [u8; 32] {
    //let mut R_sorted = R.into_iter().collect::<Vec<Message>>();
    let mut R_sorted: BTreeSet<Message> = BTreeSet::new();
    for msg in R.iter() {
        R_sorted.insert(msg.clone());
    }
    let mut hasher = Sha256::new();
    let iterator = R_sorted.iter();
    hasher.update(hash_key_prime);  
    for message in iterator {
        let usize_for_env = size_of::<usize>();
        let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&message.ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&message.ordinal.index.to_be_bytes());
        hasher.update(&ordinal_as_bytes);
        hasher.update(&ordinal_as_bytes);
        hasher.update(&message.content);
    }
    // read hash digest and consume hasher
    return hasher.finalize().try_into().unwrap();

}

fn opti_get_hash_msg_set(R: &HashSet<Message>, hash_key_prime: &[u8; 32]) -> [u8; 32] {
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    let usize_for_env = size_of::<usize>();
    
    for message in R.iter() {
        let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&message.ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&message.ordinal.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
        multiset_hash.add(&message.content, 1);
    }
    return multiset_hash.finalize();
}

fn opti_get_hash_ordinal_set(R: &HashSet<Ordinal>) -> [u8;32] {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    for ord in R.iter() {
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ord.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ord.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
    }
    
    return multiset_hash.finalize();
}

fn updated_ordinal_hash(ord: &Ordinal, prev_hash: &[u8;32]) -> [u8;32] {
    let mut result: [u8;32] = [0;32];
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    let mut hasher = Blake2s256::new();
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ord.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ord.index.to_be_bytes());
    hasher.update(&ordinal_as_bytes);
    let ord_hash: [u8;32] = hasher.finalize().try_into().unwrap();
    let new_hash: Vec<u8> = ord_hash.iter().zip(prev_hash.iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();
    result.clone_from_slice(&new_hash);
    return result;
}

fn get_hash_ordinal_set(R: &HashSet<Ordinal>) -> [u8; 32] {
    let mut R_sorted : BTreeSet<Ordinal> = BTreeSet::new();
    for ordinal in R.iter() {
        R_sorted.insert(ordinal.clone());
    }
    let mut hasher = Sha256::new();
    let iterator = R_sorted.iter();  
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    for ordinal in iterator {
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ordinal.index.to_be_bytes());
        hasher.update(&ordinal_as_bytes);
    }
    return hasher.finalize().try_into().unwrap();

}


pub fn rrc_send(state: &mut RrcState, associated_data: &[u8; 32], plaintext: &[u8]) -> (Ordinal, Ciphertext, Header) {
    let mut nums_prime: HashSet<Ordinal> = HashSet::new();
    for msg in state.R.iter() {
        nums_prime.insert(msg.ordinal);
    }
    let R_prime: (HashSet<Ordinal>, [u8; 32]) = (nums_prime.clone(), get_hash_msg_set(&state.R, state.hash_key_prime));
    let mut associated_data_prime: [u8; 128] = [0;128];
    // TODO: change way of computing associated data to reduce overhead, xor messages instead of hashing for ex, idem for ordinal
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&state.S, [0;32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&R_prime.0));
    associated_data_prime[96..128].clone_from_slice(&R_prime.1);

    let sent: (Ordinal, Header, Vec<u8>) = send(&mut state.state, &associated_data_prime, plaintext);
    let ciphertext: Ciphertext = Ciphertext{ciphertext: sent.2, S: state.S.clone(), R: (nums_prime, R_prime.1.clone())};

    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&sent.0.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&sent.0.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ciphertext.ciphertext);
    hasher.update(get_hash_msg_set(&ciphertext.S, [0;32]));
    hasher.update(get_hash_ordinal_set(&ciphertext.R.0));
    hasher.update(&ciphertext.R.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();
    state.S.insert(Message{ordinal: sent.0, content: h});

    return (sent.0, ciphertext, sent.1);
}

pub fn rrc_receive(state: &mut RrcState, associated_data: &[u8; 32], ct: &mut Ciphertext, header: Header) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 128] = [0;128];

    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&ct.S, [0;32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&ct.R.0));
    associated_data_prime[96..128].clone_from_slice(&ct.R.1);

    let (acc, num, pt) = receive(&mut state.state, &associated_data_prime, header, &ct.ciphertext);
    
    if !acc {
        println!("Failed in RC receive already");
        return (false, num, Vec::new());
    }
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.ciphertext);
    hasher.update(get_hash_msg_set(&ct.S, [0;32]));
    hasher.update(get_hash_ordinal_set(&ct.R.0));
    hasher.update(&ct.R.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();
    if checks(state, ct, &h, num) {
        println!("Checks failed");
        return (false, num, Vec::new());
    }

    state.R.insert(Message { ordinal: num, content: h });
    //state.S_ack.insert(Message { ordinal:Ordinal { epoch: header.epoch, index: header.msg_nbr }, content: h });
    let _ = &ct.S.iter().for_each(|elem| { state.S_ack.insert(elem.clone());});
    return (acc, num, pt);

} 

#[derive(Clone, PartialEq)]
pub enum Security {
    RRid,
    SRid,
    RRidAndSRid
}

fn checks(state: &mut RrcState, ct: &mut Ciphertext, h: &[u8; 32], num: Ordinal) -> bool {
    let mut s_bool: bool = false;
    let mut r_bool: bool = false;

    if state.security_level != Security::RRid {
        let mut R_star: HashSet<Message> = HashSet::new();
        for num_prime in state.S.iter() {
            if ct.R.0.contains(&num_prime.ordinal) {
                R_star.insert(num_prime.clone());
            }
        }
        s_bool = get_hash_msg_set(&R_star, state.hash_key_prime) != ct.R.1;
        if state.security_level == Security::SRid {
            return s_bool;
        }
    }
    let mut R_prime: HashSet<Message> = HashSet::new();
    for num_prime in state.R.iter() {
        if num_prime.ordinal <= num {
            R_prime.insert(num_prime.clone());
        }
    }
    r_bool = !R_prime.is_subset(&ct.S);
    r_bool = r_bool || ct.S.iter().fold(false, |acc, msg| acc || msg.ordinal >= num);
    //println!("r_bool before if else {}", r_bool);
    if num < state.max_num {
        r_bool = r_bool || !state.S_ack.contains(&Message { ordinal: num, content: h.to_owned()});
        //println!("r_bool after s_ack contains msg{}", r_bool);
        r_bool = r_bool || !ct.S.is_subset(&state.S_ack);
        //println!("r_bool after s_ack superset of S{}", r_bool);
        let mut S_ack_prime: HashSet<Message> = HashSet::new();
        for acked_msg in state.S_ack.iter() {
            if acked_msg.ordinal < num {
                S_ack_prime.insert(acked_msg.clone());
            }
        }
        r_bool = r_bool || !S_ack_prime.is_subset(&ct.S);
        //println!("r_bool after S superset of S_ack{}", r_bool);
    }
    else {
        state.max_num = num;
        r_bool = r_bool || state.S_ack.difference(&ct.S).into_iter().fold(false, |acc, msg| acc || msg.ordinal < state.max_num); // -> potential fix
        // r_bool = r_bool || ct.S.difference(&state.S_ack).into_iter().fold(false, |acc, msg| acc || msg.ordinal < state.max_num);                      -> original paper
        //println!("r_bool in else {}", r_bool);
    }

    //println!("s_bool is {}, r_bool is {}", s_bool, r_bool);
    match state.security_level {
        Security::RRid => r_bool,
        Security::RRidAndSRid => r_bool || s_bool,
        Security::SRid => return s_bool
        
    }
}

fn optimized_checks(state: &mut RrcState, ct: &mut OptimizedSendCiphertext, h: &[u8; 32], num: Ordinal) -> bool {
    let mut s_bool: bool = false;
    let mut r_bool: bool = false;

    if state.security_level != Security::RRid {
        let mut R_star: HashSet<Message> = HashSet::new();
        for num_prime in state.S.iter() {
            if ct.R.0.contains(&num_prime.ordinal) {
                R_star.insert(num_prime.clone());
            }
        }
        s_bool = !incremental_hash_sets_are_equal(incremental_hash_fct_of_whole_set(&R_star, &state.hash_key_prime), ct.R.1, &state.hash_key_prime);
        if state.security_level == Security::SRid {
            return s_bool;
        }
    }
    let mut R_prime: HashSet<Message> = HashSet::new();
    for num_prime in state.R.iter() {
        if num_prime.ordinal <= num {
            R_prime.insert(num_prime.clone());
        }
    }
    r_bool = !R_prime.is_subset(&ct.S);
    r_bool = r_bool || ct.S.iter().fold(false, |acc, msg| acc || msg.ordinal >= num);
    if num < state.max_num {
        r_bool = r_bool || !state.S_ack.contains(&Message { ordinal: num, content: h.to_owned()});
        r_bool = r_bool || !ct.S.is_subset(&state.S_ack);
        let mut S_ack_prime: HashSet<Message> = HashSet::new();
        for acked_msg in state.S_ack.iter() {
            if acked_msg.ordinal < num {
                S_ack_prime.insert(acked_msg.clone());
            }
        }
        r_bool = r_bool || !S_ack_prime.is_subset(&ct.S);
    }
    else {
        state.max_num = num;
        r_bool = r_bool || state.S_ack.difference(&ct.S).into_iter().fold(false, |acc, msg| acc || msg.ordinal < state.max_num);
    }

    match state.security_level {
        Security::RRid => r_bool,
        Security::RRidAndSRid => r_bool || s_bool,
        Security::SRid => return s_bool
        
    }
}

/* Generates a 256bit random nonce used for the incremental hash function
 * Hash function 0 is SHA256, Hash function 1 is Blake2s256.
 */
fn generate_nonce() -> [u8; m_bytes] {
    let mut nonce = [0u8; m_bytes];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut nonce);
    return nonce;
}



const m: usize = 256 + 24; // We support 2^24 messages with hashes of 256 bits
const m_bytes: usize = m / 8;
/*
 * Hash function 0 is SHA256, Hash function 1 is Blake2s256.
 * Generates a triple [h, c, r] as stated in https://people.csail.mit.edu/devadas/pubs/mhashes.pdf
 * Implements the Mset-XOR-Hash.
 */
fn incremental_hash_fct_of_whole_set(R: &HashSet<Message>, hash_key_prime: &[u8; 32]) -> [u8; 32 + 2 * m_bytes] {
    let mut hash: [u8; 32 + 2 * m_bytes] = [0;32 + 2 * m_bytes];
    let nonce = generate_nonce();
    hash[32 + m_bytes..32 + 2 * m_bytes].clone_from_slice(&nonce);
    
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&nonce);
    let mut h: [u8;32] = hasher.finalize().try_into().unwrap();

    // Order in which messages are iterated isn't relevant since xor is commutative.
    for msg in R.iter() {
        let mut hashed_msg = hash_msg_w_blake2(msg, &hash_key_prime);
        let xored: Vec<u8> = h.iter().zip(hashed_msg.iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();
        h = xored.try_into().unwrap();
    }

    hash[0..32].clone_from_slice(&h);
    let usize_for_env = size_of::<usize>();
    // Here the has fct protocol says to take modulo 2^m but usize we already have modulo usize MAX_VALUE.
    let nbr_elems_in_R_bytes = (R.len()).to_be_bytes();
    let mut correct_size_nbr_elems = [0; m_bytes];
    // ????? is this really correct
    correct_size_nbr_elems[m_bytes - usize_for_env..m_bytes].clone_from_slice(&nbr_elems_in_R_bytes);
    hash[32..32 + m_bytes].clone_from_slice(&correct_size_nbr_elems);

    return hash;
}

fn hash_msg_w_blake2(msg: &Message, hash_key_prime: &[u8; 32]) -> [u8;32] {
    let mut hasher = Blake2s256::new();
    hasher.update(&hash_key_prime);
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&msg.ordinal.index.to_be_bytes());
    hasher.update(&ordinal_as_bytes);
    hasher.update(&msg.content);
    return hasher.finalize().try_into().unwrap();
}

/*Hash function 0 is SHA256, Hash function 1 is Blake2s256 */
fn incremental_hash_sets_are_equal(hash1: [u8; 32 + 2 * m_bytes], hash2: [u8; 32 + 2 * m_bytes], hash_key_prime: &[u8; 32]) -> bool {
    // define hash of H(0,r)
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&hash1[32 + m_bytes..32 + 2 * m_bytes]);
    let h_0_r1: [u8; 32] = hasher.finalize().try_into().unwrap();
    let xored1: Vec<u8> = h_0_r1.iter().zip(hash1[0..32].iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();

    // define hash of H(0,r')
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&hash2[32 + m_bytes..32 + 2 * m_bytes]);
    let h_0_r2: [u8; 32] = hasher.finalize().try_into().unwrap();
    let xored2: Vec<u8> = h_0_r2.iter().zip(hash2[0..32].iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();
    // check if hash1[h] xor hash_r == hash2[h] xor hash_r'
    // check if hash1[c] == hash2[c]
    return xored1 == xored2 && hash1[32..32 + m_bytes] == hash2[32..32 + m_bytes];
}

fn update_incremental_hash_set(incremental_hash: &mut [u8; 32 + 2 * m_bytes], msg: Message, hash_key_prime: &[u8; 32]) -> [u8; 32 + 2 * m_bytes] {
    let mut new_hash: [u8; 32 + 2 * m_bytes] = [0; 32 + 2 * m_bytes];
    // Update the first element in the tuple
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&incremental_hash[32 + m_bytes..32 + 2 * m_bytes]);
    let h_0_r: [u8; 32] = hasher.finalize().try_into().unwrap();
    let hash_without_nonce_hash: Vec<u8> = h_0_r.iter().zip(incremental_hash[0..32].iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect(); 
    let msg_hash = hash_msg_w_blake2(&msg, hash_key_prime);
    let new_h_without_xor_nonce: Vec<u8> = msg_hash.iter().zip(hash_without_nonce_hash.iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();

    // Update the second element (cardinality of set)
    let usize_for_env = size_of::<usize>();
    let mut cardinality_R: usize = usize::from_be_bytes(incremental_hash[32 + m_bytes - usize_for_env..32 + m_bytes].try_into().unwrap());
    cardinality_R += 1;
    let nbr_elems_in_R_bytes = (cardinality_R).to_be_bytes();
    let mut correct_size_nbr_elems = [0; m_bytes];
    correct_size_nbr_elems[m_bytes - usize_for_env..m_bytes].clone_from_slice(&nbr_elems_in_R_bytes);
    new_hash[32..32 + m_bytes].clone_from_slice(&correct_size_nbr_elems);

    let nonce = generate_nonce();
    new_hash[32 + m_bytes..32 + 2 * m_bytes].clone_from_slice(&nonce);
    hasher = Sha256::new();
    hasher.update(hash_key_prime);
    hasher.update(nonce);
    let hash_nonce: [u8; 32] = hasher.finalize().try_into().unwrap();
    let new_h: Vec<u8> = new_h_without_xor_nonce.iter().zip(hash_nonce.iter()).map(|(&byte1, &byte2)| byte1 ^ byte2).collect();
    new_hash[0..32].clone_from_slice(&new_h);

    return new_hash;
}

pub fn optimized_rrc_send(state: &mut OptimizedSendRrcState, associated_data: &[u8; 32], plaintext: &[u8]) -> (Ordinal, OptimizedSendCiphertext, Header) {
    let R_prime: (HashSet<Ordinal>, [u8; 32 + 2 * m_bytes]) = (state.nums_prime.clone(), state.incremental_hash);
    let mut associated_data_prime: [u8; 128 + 2 * m_bytes] = [0;128 + 2 * m_bytes];
    associated_data_prime[0..32].clone_from_slice(associated_data);
    //associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&state.state.S, [0;32]));
    associated_data_prime[32..64].clone_from_slice(&state.hash_S.clone().finalize());
    //associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&R_prime.0));
    associated_data_prime[64..96].clone_from_slice(&state.hash_ordinal_set.clone().finalize());
    associated_data_prime[96..128 + 2 * m_bytes].clone_from_slice(&R_prime.1);


    let sent: (Ordinal, Header, Vec<u8>) = send(&mut state.state.state, &associated_data_prime, plaintext);
    let ciphertext: OptimizedSendCiphertext = OptimizedSendCiphertext { ciphertext: sent.2, S: state.state.S.clone(), R: (state.nums_prime.clone(), R_prime.1.clone())};

    let mut hasher = Sha256::new();
    hasher.update(&state.state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&sent.0.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&sent.0.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ciphertext.ciphertext);
    //hasher.update(get_hash_msg_set(&ciphertext.S, [0;32]));
    hasher.update(&state.hash_S.clone().finalize());
    hasher.update(state.hash_ordinal_set.clone().finalize());
    //hasher.update(get_hash_ordinal_set(&ciphertext.R.0));
    hasher.update(&ciphertext.R.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    let new_msg = Message{ordinal: sent.0, content: h};
    state.state.S.insert(new_msg.clone());



    // Update the hash of all sent messages using the new message
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&new_msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&new_msg.ordinal.index.to_be_bytes());
    state.hash_S.add(&ordinal_as_bytes, 1);
    state.hash_S.add(&new_msg.content, 1);
    
    return (sent.0, ciphertext, sent.1);
}

pub fn optimized_rrc_receive(state: &mut OptimizedSendRrcState, associated_data: &[u8; 32], ct: &mut OptimizedSendCiphertext, header: Header) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 128 + 2 * m_bytes] = [0;128 + 2 * m_bytes];

    let hash_sent_ct = opti_get_hash_msg_set(&ct.S, &[0u8;32]);

    associated_data_prime[0..32].clone_from_slice(associated_data);
    //associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&ct.S, [0;32]));
    associated_data_prime[32..64].clone_from_slice(&hash_sent_ct);
    //associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&ct.R.0));
    // TODO: change opti_get_hash_ordinal_set to correspond to multiset hashing, also change opti get hash msg set
    associated_data_prime[64..96].clone_from_slice(&opti_get_hash_ordinal_set(&ct.R.0));
    associated_data_prime[96..128 + 2 * m_bytes].clone_from_slice(&ct.R.1);

    let (acc, num, pt) = receive(&mut state.state.state, &associated_data_prime, header, &ct.ciphertext);
    
    if !acc {
        println!("Failed in RC receive already");
        return (false, num, Vec::new());
    }
    let mut hasher = Sha256::new();
    hasher.update(&state.state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.ciphertext);
    //hasher.update(get_hash_msg_set(&ct.S, [0;32]));
    hasher.update(&hash_sent_ct);
    hasher.update(opti_get_hash_ordinal_set(&ct.R.0));
    //hasher.update(get_hash_ordinal_set(&ct.R.0));
    hasher.update(&ct.R.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();
    if optimized_checks(&mut state.state, ct, &h, num) {
        println!("Checks failed");
        return (false, num, Vec::new());
    }

    let msg = Message { ordinal: num, content: h };
    state.state.R.insert(msg.clone());
    state.nums_prime.insert(msg.ordinal.clone());

    // Update hash of ordinals you've received using multiset hash
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&msg.ordinal.index.to_be_bytes());
    state.hash_ordinal_set.add(&ordinal_as_bytes, 1);
    //state.hash_ordinal_set = updated_ordinal_hash(&msg.ordinal.clone(), &state.hash_ordinal_set);
    state.incremental_hash = update_incremental_hash_set(&mut state.incremental_hash, msg, &state.state.hash_key_prime);
    //state.S_ack.insert(Message { ordinal:Ordinal { epoch: header.epoch, index: header.msg_nbr }, content: h });
    let _ = &ct.S.iter().for_each(|elem| { state.state.S_ack.insert(elem.clone());});
    return (acc, num, pt);

} 

fn send_bytes(state: &mut RrcState, associated_data: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // 1. Call send to obtain encrypted message as objects
    let (num, ct, header) = rrc_send(state, associated_data, plaintext);
    // 2. Get size of each individual element we will encode
    // 2.1 Everything for the ciphertext object
    let msg_ct_len = ct.ciphertext.len();
    let ct_s_as_bytes = ct.S.encode::<u8>().unwrap();
    let s_len = ct_s_as_bytes.len();
    let ct_r_ord_set_as_bytes = ct.R.0.encode::<u8>().unwrap();
    let r_ord_set_len = ct_r_ord_set_as_bytes.len();
    let ct_len = msg_ct_len + s_len + r_ord_set_len + 32;    // + 32 bytes for r_1
    // 2.2 Everything for the header
    let dh_pk_len: usize = header.dh_ratchet_key.to_bytes().len();
    let header_len: usize = dh_pk_len + 3 * size_of::<usize>();    // + 3 * usize
    // 2.3 Ordinal takes 2 * usize_for_env
    let ordinal_len: usize = 2 * size_of::<usize>();
    // 3. Allocate a buffer for all of the elements
    let metadata_len = 3 * size_of::<usize>(); // To store ciphertext, s, and r_0's lenghts in the encoded form
    let total_len = header_len + ordinal_len + ct_len + metadata_len;
    let mut bytes = vec![0u8; total_len];
    // 4. Fit the elements into the buffer
    // 4.1 The header: dh_pk || prev_chain_len || msg_nbr || epoch
    bytes[0..32].clone_from_slice(header.dh_ratchet_key.as_bytes());
    bytes[32..32 + size_of::<usize>()].clone_from_slice(&header.prev_chain_len.to_be_bytes());
    bytes[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()].clone_from_slice(&header.msg_nbr.to_be_bytes());
    bytes[32 + 2 * size_of::<usize>()..header_len].clone_from_slice(&header.epoch.to_be_bytes());
    // 4.2 The ordinal: epoch || index
    bytes[header_len..header_len + size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    bytes[header_len + size_of::<usize>()..header_len + ordinal_len].clone_from_slice(&num.index.to_be_bytes());
    // 4.3 The ciphertext: ct_len || s_len || r_0_len || ct || s || r_0 || r_1
    bytes[header_len + ordinal_len..header_len + ordinal_len + size_of::<usize>()].clone_from_slice(&msg_ct_len.to_be_bytes());
    bytes[header_len + ordinal_len + size_of::<usize>()..header_len + ordinal_len + 2 * size_of::<usize>()].clone_from_slice(&s_len.to_be_bytes());
    bytes[header_len + ordinal_len + 2 * size_of::<usize>()..header_len + ordinal_len + metadata_len].clone_from_slice(&r_ord_set_len.to_be_bytes());
    bytes[header_len + ordinal_len + metadata_len..header_len + ordinal_len + metadata_len + msg_ct_len].clone_from_slice(&ct.ciphertext);
    bytes[header_len + ordinal_len + metadata_len + msg_ct_len..header_len + ordinal_len + metadata_len + msg_ct_len + s_len].clone_from_slice(&ct_s_as_bytes);
    bytes[header_len + ordinal_len + metadata_len + msg_ct_len + s_len..header_len + ordinal_len + metadata_len + msg_ct_len + s_len + r_ord_set_len].clone_from_slice(&ct_r_ord_set_as_bytes);
    bytes[total_len - 32..total_len].clone_from_slice(&ct.R.1);

    return bytes;
    
}

fn receive_bytes(payload: &[u8], state: &mut RrcState, associated_data: &[u8; 32]) -> (bool, Ordinal, Vec<u8>) {
    // 1. Decode header
    let mut pk_bytes = [0u8; 32];
    pk_bytes.clone_from_slice(&payload[0..32]);
    let header = Header { dh_ratchet_key: PublicKey::from(pk_bytes), prev_chain_len: usize::from_be_bytes(payload[32..32 + size_of::<usize>()].try_into().unwrap()), msg_nbr: usize::from_be_bytes(payload[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()].try_into().unwrap()), epoch: usize::from_be_bytes(payload[32 + 2 * size_of::<usize>()..32 + 3 * size_of::<usize>()].try_into().unwrap()) };
    // 2. Decode ciphertext
    let ct_meta_offset = 32 + 5 * size_of::<usize>();
    let ct_len = usize::from_be_bytes(payload[ct_meta_offset..ct_meta_offset + size_of::<usize>()].try_into().unwrap());
    let s_len = usize::from_be_bytes(payload[ct_meta_offset + size_of::<usize>()..ct_meta_offset + 2 * size_of::<usize>()].try_into().unwrap());;
    let r_0_len = usize::from_be_bytes(payload[ct_meta_offset + 2 * size_of::<usize>()..ct_meta_offset + 3 * size_of::<usize>()].try_into().unwrap());

    let ct_offset = ct_meta_offset + 3 * size_of::<usize>();
    let s: HashSet<Message> = HashSet::decode::<u8>(&payload[ct_offset + ct_len..ct_offset + ct_len + s_len]).unwrap();
    let r_0: HashSet<Ordinal> = HashSet::decode::<u8>(&payload[ct_offset + ct_len + s_len..ct_offset + ct_len + s_len + r_0_len]).unwrap();
    let mut r_1 = [0u8; 32];
    r_1.clone_from_slice(&payload[ct_offset + ct_len + s_len + r_0_len..payload.len()]);
    let mut ct = Ciphertext { ciphertext: payload[ct_offset..ct_offset + ct_len].to_vec(), S: s, R: (r_0, r_1) };
    return rrc_receive(state, associated_data, &mut ct, header);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_receive_bytes_works() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let mut associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let bytes = send_bytes(&mut alice_state, &associated_data, plaintext);
        let (acc, ordinal, decrypted_plaintext) = receive_bytes(&bytes, &mut bob_state, &associated_data);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }

    #[test]
    fn hash_set_into_byte_array_works_for_associated_data() {
        let mut test_hash_set: HashSet<Vec<u8>> = HashSet::new();
        test_hash_set.insert(b"salut".to_vec());
        test_hash_set.insert(b"tranquille le sang".to_vec());
        let test = test_hash_set.encode::<u8>().unwrap();
        let result_hash_set: HashSet<Vec<u8>> = HashSet::decode::<u8>(&test).unwrap();
        assert_eq!(result_hash_set.contains(&b"tranquille le sang".to_vec()), true);
        assert_eq!(result_hash_set.contains(&b"salut".to_vec()), true);
        assert_eq!(result_hash_set.contains(&b"impossible n'est pas francais".to_vec()), false);
    }

    #[test]
    fn get_hash_of_set_of_msgs_works() {
        let mut first_set: HashSet<Message> = HashSet::new();
        let mut second_set: HashSet<Message> = HashSet::new();

        let first_msg = Message{content: [17;32], ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: [15; 32], ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: [244;32], ordinal: Ordinal { epoch: 5, index: 0 }};

        first_set.insert(first_msg);
        first_set.insert(second_msg);
        first_set.insert(third_msg);

        let first_msg = Message{content: [17; 32], ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: [15;32], ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: [244;32], ordinal: Ordinal { epoch: 5, index: 0 }};

        second_set.insert(third_msg);
        second_set.insert(first_msg);
        second_set.insert(second_msg);

        let hash_key_prime: [u8;32] = [0;32];

        assert_eq!(get_hash_msg_set(&first_set, hash_key_prime), get_hash_msg_set(&second_set, hash_key_prime));
        
    }

    #[test]
    fn get_hash_of_set_of_msgs_fails_when_it_should() {
        let mut first_set: HashSet<Message> = HashSet::new();
        let mut second_set: HashSet<Message> = HashSet::new();

        let first_msg = Message{content: [17;32], ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: [15; 32], ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: [244;32], ordinal: Ordinal { epoch: 5, index: 0 }};

        first_set.insert(first_msg);
        first_set.insert(second_msg);
        first_set.insert(third_msg);

        let first_msg = Message{content: [17; 32], ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: [15;32], ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: [244;32], ordinal: Ordinal { epoch: 5, index: 1 }};

        second_set.insert(third_msg);
        second_set.insert(first_msg);
        second_set.insert(second_msg);

        let hash_key_prime: [u8;32] = [0;32];

        assert_ne!(get_hash_msg_set(&first_set, hash_key_prime), get_hash_msg_set(&second_set, hash_key_prime));
        
    }

    #[test]
    fn get_hash_of_set_of_ordinals_works() {
        let mut first_set: HashSet<Ordinal> = HashSet::new();
        let mut second_set: HashSet<Ordinal> = HashSet::new();

        let first_msg = Ordinal { epoch: 3, index: 17 };
        let second_msg = Ordinal { epoch: 3, index: 19 };

        first_set.insert(first_msg);
        first_set.insert(second_msg);

        let first_msg = Ordinal { epoch: 3, index: 17 };
        let second_msg = Ordinal { epoch: 3, index: 19 };

        second_set.insert(second_msg);
        second_set.insert(first_msg);

        let hash_key_prime: [u8;32] = [0;32];

        assert_eq!(get_hash_ordinal_set(&first_set), get_hash_ordinal_set(&second_set));
    }

    #[test]
    fn get_hash_of_set_of_ordinals_fails_when_it_should() {
        let mut first_set: HashSet<Ordinal> = HashSet::new();
        let mut second_set: HashSet<Ordinal> = HashSet::new();

        let first_msg = Ordinal { epoch: 3, index: 17 };
        let second_msg = Ordinal { epoch: 3, index: 19 };

        first_set.insert(first_msg);
        first_set.insert(second_msg);

        let first_msg = Ordinal { epoch: 3, index: 18 };
        let second_msg = Ordinal { epoch: 3, index: 19 };

        second_set.insert(second_msg);
        second_set.insert(first_msg);

        let hash_key_prime: [u8;32] = [0;32];

        assert_ne!(get_hash_ordinal_set(&first_set), get_hash_ordinal_set(&second_set));
    }

    

    #[test]
    fn ordinal_ordering_works() {
        assert_eq!(true, Ordinal{epoch: 2, index:1} < Ordinal{epoch: 2, index:2});
        assert_eq!(true, Ordinal{epoch: 1, index:25} < Ordinal{epoch: 2, index:1});
        assert_eq!(Ordinal{epoch:10, index:5}, Ordinal{epoch:10, index:5});
    }

    #[test]
    fn send_and_receive_normal_functioning() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let mut associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext);
        let (acc, ordinal, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let plaintext_2 = b"Let me ping you again";
        let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext_2);
        let (acc, ordinal, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_2.to_vec(), decrypted_plaintext);

        let plaintext_3 = b"My bad I missed your first message! Let me call you back";
        let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, plaintext_3);
        let (acc, ordinal, decrypted_plaintext) = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_3.to_vec(), decrypted_plaintext);
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude?";
        let plaintext2 = b"Wassup my dude2?";
        let plaintext3 = b"Wassup my dude3?";
        let plaintext4 = b"Wassup my dude4?";
        let plaintext5 = b"Wassup my dude5?";

        let mut ct1 = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let mut ct2 = rrc_send(&mut alice_state, &associated_data, plaintext2);
        let mut ct3 = rrc_send(&mut alice_state, &associated_data, plaintext3);
        let mut ct4 = rrc_send(&mut alice_state, &associated_data, plaintext4);
        let mut ct5 = rrc_send(&mut alice_state, &associated_data, plaintext5);

        let pt5 = rrc_receive(&mut bob_state, &associated_data, &mut ct5.1, ct5.2);
        assert_eq!(pt5.0, true);
        assert_eq!(plaintext5.to_vec(), pt5.2);

        let pt1 = rrc_receive(&mut bob_state, &associated_data, &mut ct1.1, ct1.2);
        assert_eq!(pt1.0, true);
        assert_eq!(plaintext1.to_vec(), pt1.2);

        let pt4 = rrc_receive(&mut bob_state, &associated_data, &mut ct4.1, ct4.2);
        assert_eq!(pt4.0, true);
        assert_eq!(plaintext4.to_vec(), pt4.2);

        let pt3 = rrc_receive(&mut bob_state, &associated_data, &mut ct3.1, ct3.2);
        assert_eq!(pt3.0, true);
        assert_eq!(plaintext3.to_vec(), pt3.2);

        let pt2 = rrc_receive(&mut bob_state, &associated_data, &mut ct2.1, ct2.2);
        assert_eq!(pt2.0, true);
        assert_eq!(plaintext2.to_vec(), pt2.2);
    }

    #[test]
    fn out_of_order_delivery_both_send() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude?";
        let plaintext2 = b"Wassup my dude2?";
        let plaintext3 = b"Wassup my dude3?";
        let plaintext4 = b"Wassup my dude4?";

        let mut ct1 = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let mut ct2 = rrc_send(&mut alice_state, &associated_data, plaintext2);

        let pt2 = rrc_receive(&mut bob_state, &associated_data, &mut ct2.1, ct2.2);
        assert_eq!(pt2.0, true);
        assert_eq!(plaintext2.to_vec(), pt2.2);

        let mut ct3 = rrc_send(&mut bob_state, &associated_data, plaintext3);
        let mut ct4 = rrc_send(&mut bob_state, &associated_data, plaintext4);

        let pt4 = rrc_receive(&mut alice_state, &associated_data, &mut ct4.1, ct4.2);
        assert_eq!(pt4.0, true);
        assert_eq!(plaintext4.to_vec(), pt4.2);

        let pt3 = rrc_receive(&mut alice_state, &associated_data, &mut ct3.1, ct3.2);
        assert_eq!(pt3.0, true);
        assert_eq!(plaintext3.to_vec(), pt3.2);

        let pt1 = rrc_receive(&mut bob_state, &associated_data, &mut ct1.1, ct1.2);
        assert_eq!(pt1.0, true);
        assert_eq!(plaintext1.to_vec(), pt1.2);
    }

    #[test]
    fn adversarial_example_is_detected_for_s_rid() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let mut eve_state = alice_state.clone();

        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude?";

        let mut malicious_msg = rrc_send(&mut eve_state, &associated_data, plaintext1);
        rrc_receive(&mut bob_state, &associated_data, &mut malicious_msg.1, malicious_msg.2);

        let plaintext2 = b"I'm fine how are you Alice?";
        let mut ciphertext1 = rrc_send(&mut bob_state, &associated_data, plaintext2);
        let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext1.1, ciphertext1.2);
        // Check that we detected that the other person received a forgery.
        assert_eq!(result.0, false);
    }

    #[test]
    fn adversarial_example_is_detected_for_r_rid() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let mut eve_state = alice_state.clone();

        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude? (fake)";

        let mut malicious_msg = rrc_send(&mut eve_state, &associated_data, plaintext1);
        rrc_receive(&mut bob_state, &associated_data, &mut malicious_msg.1, malicious_msg.2);

        let plaintext1 = b"Wassup my dude? (real)";
        let mut legit_msg = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let result = rrc_receive(&mut bob_state, &associated_data, &mut legit_msg.1, legit_msg.2);

        // Detect that we've received a forgery
        assert_eq!(result.0, false);
    }

    #[test]
    fn adversarial_example_detected_for_r_rid2() {
        // Alice sends messages
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);

        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude? 1";
        let plaintext2 = b"Wassup my dude? 2";

        let mut ct1 = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let mut ct2 = rrc_send(&mut alice_state, &associated_data, plaintext2);

        let mut incorrect_header = ct2.2.clone();
        incorrect_header.msg_nbr -= 1;
        let result = rrc_receive(&mut bob_state, &associated_data, &mut ct2.1, incorrect_header);
        assert_eq!(result.0, false);
    }

    #[test]
    fn adversarial_example_detected_for_r_rid3() {
        // If adversary corrupts whole state at given time, but Alice sends messages before adversary does.
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext1 = b"Wassup my dude? 1";
        let plaintext2 = b"Wassup my dude? 2";

        let mut ct1 = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let mut corrupted_state = alice_state.clone();
        let mut ct2 = rrc_send(&mut alice_state, &associated_data, plaintext2);

        // Alice sends another msg
        let plaintext3 = b"Wassup my dude? 3";
        let plaintext2_fake = b"I am malicious";
        let mut ct3_real = rrc_send(&mut alice_state, &associated_data, plaintext3);
        let mut ct2_fake = rrc_send(&mut corrupted_state, &associated_data, plaintext2_fake);

        // Bob receives Alice's msg 3
        let result = rrc_receive(&mut bob_state, &associated_data, &mut ct3_real.1, ct3_real.2);
        assert_eq!(result.0, true);
        assert_eq!(result.2, plaintext3.to_vec());
        // Bob receives Eve's msg 2 from corrupted state
        let corrupted_result = rrc_receive(&mut bob_state, &associated_data, &mut ct2_fake.1, ct2_fake.2);
        assert_eq!(corrupted_result.0, false);
    }

    #[test]
    fn incremental_hash_of_msg_set_works_liveness() {
        let (alice_state, bob_state) = rrc_init_all(Security::RRidAndSRid);
        let msg1 = Message{ordinal: Ordinal { epoch: 1, index: 1 }, content: [17;32]};
        let msg2 = Message{ordinal: Ordinal { epoch: 1, index: 2 }, content: [19;32]};

        let mut set1 = HashSet::new();
        set1.insert(msg1.clone());
        set1.insert(msg2.clone());
        let hash_set1 = incremental_hash_fct_of_whole_set(&set1, &alice_state.hash_key_prime);

        let mut set2 = HashSet::new();
        set2.insert(msg1);
        set2.insert(msg2);
        let hash_set2 = incremental_hash_fct_of_whole_set(&set2, &alice_state.hash_key_prime);

        assert_ne!(hash_set1, hash_set2);
        assert_eq!(true, incremental_hash_sets_are_equal(hash_set1, hash_set2, &alice_state.hash_key_prime));
    }

    #[test]
    fn incremental_hash_of_msg_set_works_safety() {
        let (alice_state, bob_state) = rrc_init_all(Security::RRidAndSRid);
        let msg1 = Message{ordinal: Ordinal { epoch: 1, index: 1 }, content: [17;32]};
        let msg2 = Message{ordinal: Ordinal { epoch: 1, index: 2 }, content: [19;32]};

        let mut set1 = HashSet::new();
        set1.insert(msg1.clone());
        set1.insert(msg2.clone());
        let mut hash_set1 = incremental_hash_fct_of_whole_set(&set1, &alice_state.hash_key_prime);

        let mut set2 = HashSet::new();
        set2.insert(msg1);
        let msg3 = Message { ordinal: Ordinal { epoch: 17, index: 132 }, content: [0;32] };
        set2.insert(msg3.clone());
        let mut hash_set2 = incremental_hash_fct_of_whole_set(&set2, &alice_state.hash_key_prime);

        assert_ne!(hash_set1, hash_set2);
        assert_eq!(false, incremental_hash_sets_are_equal(hash_set1, hash_set2, &alice_state.hash_key_prime));

        set2.remove(&msg3);
        set2.insert(msg2);
        hash_set2 = incremental_hash_fct_of_whole_set(&set2, &alice_state.hash_key_prime);
        assert_ne!(hash_set1, hash_set2);
        assert_eq!(true, incremental_hash_sets_are_equal(hash_set1, hash_set2, &alice_state.hash_key_prime));

        set2.insert(msg3);
        hash_set2 = incremental_hash_fct_of_whole_set(&set2, &alice_state.hash_key_prime);
        assert_ne!(hash_set1, hash_set2);
        assert_eq!(false, incremental_hash_sets_are_equal(hash_set1, hash_set2, &alice_state.hash_key_prime));
    }

    #[test]
    fn adding_to_set_computes_correct_hash() {
        let (alice_state, bob_state) = rrc_init_all(Security::RRidAndSRid);
        let msg1 = Message{ordinal: Ordinal { epoch: 1, index: 1 }, content: [17;32]};
        let msg2 = Message{ordinal: Ordinal { epoch: 1, index: 2 }, content: [19;32]};

        let mut set1 = HashSet::new();
        set1.insert(msg1.clone());
        set1.insert(msg2.clone());
        let mut hash_set1 = incremental_hash_fct_of_whole_set(&set1, &alice_state.hash_key_prime);

        let mut set2 = HashSet::new();
        set2.insert(msg1);
        let mut hash_set2 = incremental_hash_fct_of_whole_set(&set2, &alice_state.hash_key_prime);
        assert_ne!(true, incremental_hash_sets_are_equal(hash_set1, hash_set2, &alice_state.hash_key_prime));
        let new_hash_set2 = update_incremental_hash_set(&mut hash_set2, msg2, &alice_state.hash_key_prime);

        assert_ne!(new_hash_set2, hash_set1);
        assert_eq!(true, incremental_hash_sets_are_equal(hash_set1, new_hash_set2, &alice_state.hash_key_prime));
    }

    #[test]
    fn send_and_receive_optimized_normal_functioning() {
        let (mut alice_state, mut bob_state) = rrc_init_all_optimized_send(Security::RRidAndSRid);
        let mut associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext);
        let (acc, ordinal, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let plaintext_2 = b"Let me ping you again";
        let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext_2);
        let (acc, ordinal, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_2.to_vec(), decrypted_plaintext);

        let plaintext_3 = b"My bad I missed your first message! Let me call you back";
        let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, plaintext_3);
        let (acc, ordinal, decrypted_plaintext) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_3.to_vec(), decrypted_plaintext);
    }

    #[test]
    fn out_of_order_with_optimizations_works() {
        let (mut alice_state, mut bob_state) = rrc_init_all_optimized_send(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let (_, mut ct1, header1) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext);

        let plaintext_2 = b"Let me ping you again";
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext_2);

        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_2.to_vec(), decrypted_plaintext);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ct1, header1);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let plaintext_3 = b"My bad I missed your first message! Let me call you back";
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, plaintext_3);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_3.to_vec(), decrypted_plaintext);


    for i in 0..5 {
        let plaintext = (i as u8).to_be_bytes();
        let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, &plaintext);
        let (acc, ordinal, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
        let plaintext = (i*17 as u8).to_be_bytes();
        let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, &plaintext);
        let (acc, ordinal, decrypted_plaintext) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }
    }

    #[test]
    fn incremental_ristretto_hash_works_w_finalize() {
        let mut hash1 = RistrettoHash::<Sha512>::default();
        hash1.add(b"test", 1);
        let buf = hash1.clone().finalize();
        hash1.add(b"test", 1);

        let mut hash2 = RistrettoHash::<Sha512>::default();
        hash2.add(b"test", 2);

        assert_eq!(hash1.finalize(), hash2.finalize());
    }



    // The goal of this test is to have a similar benchmark to the one in "Optimal Symmetric Ratcheting for Secure Communication" p25/26
    // Since this does not actually test anything, it is not run by default: uncomment the following line to do so.
    //#[test]
    fn benchmarks_total_exec() {
        let message = b"This will be sent by both participants";
        let associated_data = [0u8;32];

        let mut file = File::create("../../../Report/Plots/BenchLogs/typesOfCommunication.txt").expect("bla");

        let NBR_DIFFERENT_RUNS = 15;

        // Alternating. Alice and Bob take turns sending messages. 
        // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
        for i in 1..NBR_DIFFERENT_RUNS + 1 {
            let total_nbr_msgs = 100 * i;
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let start = SystemTime::now();
            for msg_nbr in 0..total_nbr_msgs {
                if msg_nbr % 2 == 0 {
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                }
                else {
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
                }
            }
            file.write(i.to_string().as_bytes());
            file.write(b" ");
            file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
            file.write_all(b"\n"); 
        }

        // Unidirectional. Alice first sends n/2 messages to Bob, and after receiving them Bob responds with the remaining n/2 messages.
        for i in 1..NBR_DIFFERENT_RUNS + 1 {
            let total_nbr_msgs = 100 * i;
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let start = SystemTime::now();
            for msg_nbr in 0..total_nbr_msgs {
                if msg_nbr < total_nbr_msgs / 2 {
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                }
                else {
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
                }
            }
            file.write(i.to_string().as_bytes());
            file.write(b" ");
            file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
            file.write_all(b"\n"); 
        }

        // Deferred unidirectional. Alice first sends n/2 messages to Bob but before he receives them, Bob sends n/2 messages to Alice.
        for i in 1..NBR_DIFFERENT_RUNS + 1 {
            let total_nbr_msgs = 100 * i;
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let mut counter = 0;

            let mut alice_cts: Vec<Ciphertext> = Vec::new();
            let mut alice_headers: Vec<Header> = Vec::new();

            let mut bob_cts: Vec<Ciphertext> = Vec::new();
            let mut bob_headers: Vec<Header> = Vec::new();

            for msg_nbr in 0..total_nbr_msgs {
                if msg_nbr < total_nbr_msgs / 2 {
                    let start = SystemTime::now();
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
                    alice_cts.push(ciphertext);
                    alice_headers.push(header);
                }
                else {
                    let start = SystemTime::now();
                    let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
                    bob_cts.push(ciphertext);
                    bob_headers.push(header);
                }
            }

            for (ciphertext, header) in alice_cts.iter().zip(alice_headers.iter()) {
                let mut ct = (*ciphertext).clone();
                let start = SystemTime::now();
                let result = rrc_receive(&mut alice_state, &associated_data, &mut ct, *header);
                counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
            }

            for (ciphertext, header) in bob_cts.iter().zip(bob_headers.iter()) {
                let mut ct = (*ciphertext).clone();
                let start = SystemTime::now();
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ct, *header);
                counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
            }

            file.write(i.to_string().as_bytes());
            file.write(b" ");
            file.write(counter.to_string().as_bytes());
            file.write_all(b"\n"); 
        }
    }
}

