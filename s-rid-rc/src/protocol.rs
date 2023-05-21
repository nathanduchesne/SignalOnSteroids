use std::collections::HashSet;

use mset_mu_hash::RistrettoHash;
use rc::{State, Ordinal, init_all, generate_dh, dh, send, Header, receive};
use rrc::Message;
use sha2::{Sha256, Sha512, Digest};
use std::mem::size_of;
use bytevec::{ByteEncodable, ByteDecodable};
use x25519_dalek::PublicKey;



#[derive(Clone)]
pub struct SRidState {
    pub state: State,
    pub hash_key: [u8; 32],
    pub hash_key_prime: [u8; 32],
    pub s: HashSet<Message>,
    pub r: HashSet<Message>,
    pub fresh_r: HashSet<Message>,
    pub max_num: Ordinal,
    pub epoch: usize,
    pub acked_epoch: usize,
    pub nums_prime: HashSet<Ordinal>,
    pub fresh_nums_prime: HashSet<Ordinal>,
    pub incremental_hash: RistrettoHash<Sha512>,
    pub fresh_incremental_hash: RistrettoHash<Sha512>,
    pub hash_ordinal_set: RistrettoHash<Sha512>,
    pub fresh_ordinal_set_hash: RistrettoHash<Sha512>
}

#[derive(Clone)]
pub struct OptimizedSendCiphertext {
    pub ciphertext: Vec<u8>,
    pub epoch: usize,
    pub r_prime: (HashSet<Ordinal>, [u8;32]),
    pub header: Header
}

/// Send wrapper which encodes the whole package payload into a byte array.
/// 
/// Should be decoded and received using the s_rid_rc_receive_bytes() function 
pub fn s_rid_rc_send_bytes(state: &mut SRidState, associated_data: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let (_, opti_ct) = s_rid_rc_send(state, associated_data, plaintext);

    // 1. Calculate total length for buffer
    let ct_len = opti_ct.ciphertext.len();
    let r_prime_0 = opti_ct.r_prime.0.encode::<u32>().unwrap();
    let r_prime_0_len = r_prime_0.len();
    let header_len = 32 + 3 * size_of::<usize>();
    let metadata_len = 3 * size_of::<usize>();
    // header || epoch || ct_len || r_prime_0_len || ct || r_prime_0 || r_prime_1
    let total_buf_len = header_len + metadata_len + ct_len + r_prime_0_len + 32;
    let mut bytes = vec![0u8; total_buf_len];

    // Header
    bytes[0..32].clone_from_slice(opti_ct.header.dh_ratchet_key.as_bytes());
    bytes[32..32 + size_of::<usize>()].clone_from_slice(&opti_ct.header.prev_chain_len.to_be_bytes());
    bytes[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()].clone_from_slice(&opti_ct.header.msg_nbr.to_be_bytes());
    bytes[32 + 2 * size_of::<usize>()..header_len].clone_from_slice(&opti_ct.header.epoch.to_be_bytes());
    // Epoch
    bytes[header_len..header_len + size_of::<usize>()].clone_from_slice(&opti_ct.epoch.to_be_bytes());
    // Metadata
    bytes[header_len + size_of::<usize>()..header_len + 2 * size_of::<usize>()].clone_from_slice(&ct_len.to_be_bytes());
    bytes[header_len + 2 * size_of::<usize>()..header_len + metadata_len].clone_from_slice(&r_prime_0_len.to_be_bytes());
    // Ciphertext
    bytes[header_len + metadata_len..header_len + metadata_len + ct_len].clone_from_slice(&opti_ct.ciphertext);
    // R_prime
    bytes[header_len + metadata_len + ct_len..header_len + metadata_len + ct_len + r_prime_0_len].clone_from_slice(&r_prime_0);
    bytes[header_len + metadata_len + ct_len + r_prime_0_len..total_buf_len].clone_from_slice(&opti_ct.r_prime.1);

    return bytes;
}

/// Receive wrapper which decodes a byte array into an S-RID RC package payload (ciphertext, header and metadata for forgery detection).
/// 
/// Should only be called after a call to s_rid_rc_send_bytes(), otherwise, there are no guarantees the decoding will succeed.
pub fn s_rid_rc_receive_bytes(state: &mut SRidState, associated_data: &[u8; 32], payload: &[u8]) -> (bool, Ordinal, Vec<u8>) {
    let mut pk_bytes = [0u8; 32];
    pk_bytes.clone_from_slice(&payload[0..32]);
    let ct_meta_offset = 32 + 4 * size_of::<usize>();
    let ct_len = usize::from_be_bytes(payload[ct_meta_offset..ct_meta_offset + size_of::<usize>()].try_into().unwrap());
    let r_prime_0_len = usize::from_be_bytes(payload[ct_meta_offset + size_of::<usize>()..ct_meta_offset + 2 * size_of::<usize>()].try_into().unwrap());
    let ct_offset = ct_meta_offset + 2 * size_of::<usize>();
    let r_prime_0: HashSet<Ordinal> = HashSet::decode::<u32>(&payload[ct_offset + ct_len..ct_offset + ct_len + r_prime_0_len]).unwrap();

    let ct = OptimizedSendCiphertext { ciphertext: payload[ct_offset..ct_offset + ct_len].to_vec(),
        epoch: usize::from_be_bytes(payload[32 + 3 * size_of::<usize>()..32 + 4 * size_of::<usize>()].try_into().unwrap()),
        r_prime: (r_prime_0, payload[ct_offset + ct_len + r_prime_0_len..payload.len()].try_into().unwrap()), 
        header: Header { dh_ratchet_key: PublicKey::from(pk_bytes), prev_chain_len: usize::from_be_bytes(payload[32..32 + size_of::<usize>()].try_into().unwrap()), msg_nbr: usize::from_be_bytes(payload[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()].try_into().unwrap()), epoch: usize::from_be_bytes(payload[32 + 2 * size_of::<usize>()..32 + 3 * size_of::<usize>()].try_into().unwrap()) }};
    return s_rid_rc_receive(state, associated_data, ct);
}

pub fn s_rid_rc_init() -> (SRidState, SRidState) {
    // Do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();
    let hash_key = dh(alice_hash_key, bob_hash_key.public);
    let hash_key_prime = dh(alice_hash_key_prime, bob_hash_key_prime.public);
    
    let (rc_state_alice, rc_state_bob) = init_all();

    let epoch: usize = 0;
    let acked_epoch: usize = 0;
    let max_num = Ordinal{epoch: 0, index: 0};

    // Initialize the incremental hashes with the shared hash keys
    let mut incremental_hash_alice = RistrettoHash::<Sha512>::default();
    incremental_hash_alice.add(hash_key_prime.to_bytes().clone(), 1);
    let mut incremental_hash_bob = RistrettoHash::<Sha512>::default();
    incremental_hash_bob.add(hash_key_prime.to_bytes().clone(), 1);
    // Initialize the incremental hashes for the fresh copies
    let mut fresh_incremental_hash_alice = RistrettoHash::<Sha512>::default();
    fresh_incremental_hash_alice.add(hash_key_prime.to_bytes().clone(), 1);
    let mut fresh_incremental_hash_bob = RistrettoHash::<Sha512>::default();
    fresh_incremental_hash_bob.add(hash_key_prime.to_bytes().clone(), 1);

    let state_alice = SRidState{state: rc_state_alice, hash_key: hash_key.to_bytes().clone(), hash_key_prime: hash_key_prime.to_bytes().clone(), s: HashSet::<Message>::new(), r: HashSet::<Message>::new(), fresh_r: HashSet::<Message>::new(), max_num: max_num, epoch: epoch, acked_epoch: acked_epoch, nums_prime: HashSet::new(), incremental_hash: incremental_hash_alice, hash_ordinal_set: RistrettoHash::<Sha512>::default(), fresh_nums_prime: HashSet::new(), fresh_incremental_hash: fresh_incremental_hash_alice, fresh_ordinal_set_hash: RistrettoHash::<Sha512>::default()};
    let state_bob = SRidState{state: rc_state_bob, hash_key: hash_key.to_bytes(), hash_key_prime: hash_key_prime.to_bytes(), s: HashSet::<Message>::new(), r: HashSet::<Message>::new(), fresh_r: HashSet::<Message>::new(), max_num: max_num, epoch: epoch + 1, acked_epoch: acked_epoch + 1, nums_prime: HashSet::new(),  incremental_hash: incremental_hash_bob, hash_ordinal_set: RistrettoHash::<Sha512>::default(), fresh_nums_prime: HashSet::new(), fresh_incremental_hash: fresh_incremental_hash_bob, fresh_ordinal_set_hash: RistrettoHash::<Sha512>::default()};

    return (state_alice, state_bob);
}

pub fn s_rid_rc_send(state: &mut SRidState, associated_data: &[u8; 32], plaintext: &[u8]) -> (Ordinal, OptimizedSendCiphertext){

    let r_prime: (HashSet<Ordinal>, [u8; 32]) = (state.nums_prime.clone(), state.incremental_hash.clone().finalize());
    let mut ad_prime: [u8; 96] = [0; 96];
    ad_prime[0..32].clone_from_slice(associated_data);
    ad_prime[32..64].clone_from_slice(&state.hash_ordinal_set.clone().finalize());
    ad_prime[64..96].clone_from_slice(&r_prime.1);
    
    let (num, header, ct_prime) = send(&mut state.state, &ad_prime, plaintext);
    let ct:(Vec<u8>, usize, (HashSet<Ordinal>, [u8; 32])) = (ct_prime, state.epoch, r_prime);

    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.0);
    hasher.update(&state.epoch.to_be_bytes());
    hasher.update(&state.hash_ordinal_set.clone().finalize());
    hasher.update(&state.incremental_hash.clone().finalize());
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    state.s.insert(Message { ordinal: num.clone(), content: h });
    return (num, OptimizedSendCiphertext{ciphertext: ct.0, epoch: state.epoch, r_prime: ct.2, header: header});

}

#[allow(non_snake_case)] // To allow ourselves to use the naming convention from the project paper's pseudocode.
fn opti_get_hash_msg_set(R: &HashSet<Message>, hash_key_prime: &[u8; 32]) -> [u8; 32] {
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    let usize_for_env = size_of::<usize>();
    
    multiset_hash.add(hash_key_prime, 1);
    for message in R.iter() {
        let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&message.ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&message.ordinal.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
        multiset_hash.add(&message.content, 1);
    }
    return multiset_hash.finalize();
}

pub fn checks(state: &SRidState, ct: &OptimizedSendCiphertext) -> bool {
    let mut s_bool = false;
    if ct.epoch > state.epoch + 1 {
        s_bool = true;
    }

    let mut r_star = HashSet::<Message>::new();
    for msg in state.s.iter() {
        if ct.r_prime.0.contains(&msg.ordinal) {
            r_star.insert(msg.clone());
        }
    }

    s_bool = s_bool || (opti_get_hash_msg_set(&r_star, &state.hash_key_prime) != ct.r_prime.1);

    return s_bool;
}

pub fn s_rid_rc_receive(state: &mut SRidState, associated_data: &[u8; 32], ct: OptimizedSendCiphertext) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 96] = [0; 96];
    let ordinal_hash = get_ordinal_set_hash(&ct.r_prime.0);
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&ordinal_hash);
    associated_data_prime[64..96].clone_from_slice(&ct.r_prime.1);

    let (acc, num, pt) = receive(&mut state.state, &associated_data_prime, ct.header, &ct.ciphertext);
    if !acc {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new());
    }
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.ciphertext);
    hasher.update(&ct.epoch.to_be_bytes());
    hasher.update(ordinal_hash);
    hasher.update(ct.r_prime.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    if checks(&state, &ct) {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new()); 
    }

    state.r.insert(Message { ordinal: num.clone(), content: h });
    state.nums_prime.insert(num.clone());
    update_receive_hashed(state, Message { ordinal: num.clone(), content: h}, false);
    update_ordinal_set_hash(state, num.clone(), false);
    state.fresh_r.insert(Message { ordinal: num.clone(), content: h });
    state.fresh_nums_prime.insert(num.clone());
    update_receive_hashed(state, Message { ordinal: num.clone(), content: h}, true);
    update_ordinal_set_hash(state, num.clone(), true);


    if ct.epoch == state.epoch + 1 {
        state.epoch = state.epoch + 2;
    }

    if state.epoch == state.acked_epoch + 4 {
        // Update the received sets
        state.r = state.fresh_r.clone();
        state.fresh_r.clear();
        state.acked_epoch = state.acked_epoch + 4;

        // Update ordinals of received, and hash of ordinal set
        state.nums_prime = state.fresh_nums_prime.clone();
        state.fresh_nums_prime.clear();
        state.incremental_hash = state.fresh_incremental_hash.clone();
        state.hash_ordinal_set = state.fresh_ordinal_set_hash.clone();
        state.fresh_ordinal_set_hash  = RistrettoHash::<Sha512>::default();
        state.fresh_incremental_hash = RistrettoHash::<Sha512>::default();
        state.fresh_incremental_hash.add(state.hash_key_prime, 1);
    }

    return (true, num, pt);
}

fn get_ordinal_set_hash(ordinal_set: &HashSet<Ordinal>) -> [u8; 32] {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    for ord in ordinal_set.iter() {
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ord.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ord.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
    }
    
    return multiset_hash.finalize();
}
/// Updates the state incremental hashes with the given message. is_fresh_hash indicates if we wish to update the hash functions of the current
/// received set, or if we wish to update the fresh received set.
fn update_receive_hashed(state: &mut SRidState, msg: Message, is_fresh_hash: bool) -> () {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&msg.ordinal.index.to_be_bytes());
    if is_fresh_hash {
        state.fresh_incremental_hash.add(&ordinal_as_bytes, 1);
        state.fresh_incremental_hash.add(&msg.content, 1);
    }
    else {
        state.incremental_hash.add(&ordinal_as_bytes, 1);
        state.incremental_hash.add(&msg.content, 1);
    }
}

/// Updates the state incremental hashes with the given ordinal. is_fresh_hash indicates if we wish to update the hash functions of the current
/// received ordinal set, or if we wish to update the fresh received ordinal set.
fn update_ordinal_set_hash(state: &mut SRidState, ordinal: Ordinal, is_fresh_hash: bool) -> () {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ordinal.index.to_be_bytes());
    if is_fresh_hash {
        state.fresh_ordinal_set_hash.add(&ordinal_as_bytes, 1);
    }
    else {
        state.hash_ordinal_set.add(&ordinal_as_bytes, 1);
    }
}