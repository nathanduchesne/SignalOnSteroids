use std::collections::HashSet;

use mset_mu_hash::RistrettoHash;
use rc::{State, Ordinal, init_all, generate_dh, dh, send, Header, receive};
use rrc::{Message, Ciphertext};
use sha2::{Sha256, Sha512, Digest};
use std::mem::size_of;

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
    pub incremental_hash: RistrettoHash<Sha512>,
    pub hash_ordinal_set: RistrettoHash<Sha512>,
}

#[derive(Clone)]
pub struct OptimizedSendCiphertext {
    pub ciphertext: Vec<u8>,
    pub epoch: usize,
    pub r_prime: (HashSet<Ordinal>, [u8;32]),
    pub header: Header
}

pub fn s_rid_rc_init() -> (SRidState, SRidState) {
    // do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();
    let hash_key = dh(alice_hash_key, bob_hash_key.public);
    let hash_key_prime = dh(alice_hash_key_prime, bob_hash_key_prime.public);
    
    let (mut rc_state_alice, mut rc_state_bob) = init_all();

    let epoch: usize = 0;
    let acked_epoch: usize = 0;
    let max_num = Ordinal{epoch: 0, index: 0};

    let mut incremental_hash_alice = RistrettoHash::<Sha512>::default();
    incremental_hash_alice.add(hash_key_prime.to_bytes().clone(), 1);
    let mut incremental_hash_bob = RistrettoHash::<Sha512>::default();
    incremental_hash_bob.add(hash_key_prime.to_bytes().clone(), 1);

    let mut state_alice = SRidState{state: rc_state_alice, hash_key: hash_key.to_bytes().clone(), hash_key_prime: hash_key_prime.to_bytes().clone(), s: HashSet::<Message>::new(), r: HashSet::<Message>::new(), fresh_r: HashSet::<Message>::new(), max_num: max_num, epoch: epoch, acked_epoch: acked_epoch, nums_prime: HashSet::new(), incremental_hash: incremental_hash_alice, hash_ordinal_set: RistrettoHash::<Sha512>::default()};
    let mut state_bob = SRidState{state: rc_state_bob, hash_key: hash_key.to_bytes(), hash_key_prime: hash_key_prime.to_bytes(), s: HashSet::<Message>::new(), r: HashSet::<Message>::new(), fresh_r: HashSet::<Message>::new(), max_num: max_num, epoch: epoch + 1, acked_epoch: acked_epoch + 1, nums_prime: HashSet::new(),  incremental_hash: incremental_hash_bob, hash_ordinal_set: RistrettoHash::<Sha512>::default()};

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

pub fn checks(state: &SRidState, ct: &OptimizedSendCiphertext, h: &[u8; 32], num: Ordinal) -> bool {
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
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_ordinal_set_hash(&ct.r_prime.0));
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
    hasher.update(get_ordinal_set_hash(&ct.r_prime.0));
    hasher.update(ct.r_prime.1);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    if checks(&state, &ct, &h, num) {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new()); 
    }

    state.r.insert(Message { ordinal: num.clone(), content: h });
    state.nums_prime.insert(num.clone());
    update_receive_hashed(state, Message { ordinal: num.clone(), content: h });
    update_ordinal_set_hash(state, num.clone());
    state.fresh_r.insert(Message { ordinal: num.clone(), content: h });

    if ct.epoch == state.epoch + 1 {
        state.epoch = state.epoch + 2;
    }

    if state.epoch == state.acked_epoch + 4 {
        // TODO: reset the incremental hash when updating the received sets
        state.r = state.fresh_r.clone();
        state.fresh_r.clear();
        state.acked_epoch = state.acked_epoch + 4;
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

fn update_receive_hashed(state: &mut SRidState, msg: Message) -> () {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&msg.ordinal.index.to_be_bytes());
    state.incremental_hash.add(&ordinal_as_bytes, 1);
    state.incremental_hash.add(&msg.content, 1);
}

fn update_ordinal_set_hash(state: &mut SRidState, ordinal: Ordinal) -> () {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env].clone_from_slice(&ordinal.index.to_be_bytes());
    state.hash_ordinal_set.add(&ordinal_as_bytes, 1);
}


//TODO: add elements to nums_prime in state in s_rid_rc_receive

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_w_rust_sets_for_fresh_r_into_r() {
        let mut set_one = HashSet::<Message>::new();
        set_one.insert(Message { ordinal: Ordinal { epoch: 0, index: 0 }, content: [8;32] });
        set_one.insert(Message { ordinal: Ordinal { epoch: 0, index: 1 }, content: [2;32] });

        let set_two = set_one.clone();

        set_one.clear();

        assert_eq!(set_two.len(), 2);
        assert_eq!(true, set_two.contains(&Message { ordinal: Ordinal { epoch: 0, index: 0 }, content: [8;32] }))
    }

    #[test]
    fn normal_execution_works() {
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data: [u8; 32] = [0;32];

        let plaintext_alice = b"Hello I am Alice";
        let (mut num, mut ct) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);

        let (mut acc, mut num, mut pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct);
        assert_eq!(acc, true);
        assert_eq!(pt, plaintext_alice);
        let plaintext_bob = b"Hello Alice, pleasure to meet you, I am Bobathan";
        let (num2, ct2) = s_rid_rc_send(&mut bob_state, &associated_data, plaintext_bob);

        (acc, num, pt) = s_rid_rc_receive(&mut alice_state, &associated_data, ct2);
        assert_eq!(acc, true);
        assert_eq!(pt, plaintext_bob);

    }
}
