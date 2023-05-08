use std::{collections::HashSet, mem::size_of, hash::Hash};
use rc::*;
use sha2::{Sha256, Digest};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Ord, PartialOrd)]
pub struct Message {
    pub ordinal: Ordinal,
    pub content: [u8;32]
}

pub struct ArcState {
    state: State,
    hash_key: [u8; 32],
    s: HashSet<Message>,
    r: HashSet<Message>,
    s_ack: HashSet<Message>,
    num: Ordinal,
    max_num: Ordinal
}

pub struct AuthenticationTag {
    s: HashSet<Message>,
    r: HashSet<Message>,
    num: Ordinal
}

pub fn arc_init() -> (ArcState, ArcState) {
    let (alice_rc_state, bob_rc_state) = init_all();

    // do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();
    let hash_key = dh(alice_hash_key, bob_hash_key.public);

    let alice_state = ArcState{state: alice_rc_state, hash_key: hash_key.to_bytes().clone(), s: HashSet::new(), r: HashSet::new(), s_ack: HashSet::new(), num: Ordinal { epoch: 0, index: 0 }, max_num: Ordinal { epoch: 0, index: 0 }};
    let bob_state = ArcState{state: bob_rc_state, hash_key: hash_key.to_bytes(), s: HashSet::new(), r: HashSet::new(), s_ack: HashSet::new(), num: Ordinal { epoch: 0, index: 0 }, max_num: Ordinal { epoch: 0, index: 0 }};

    return (alice_state, bob_state);
}

pub fn arc_send(state: &mut ArcState, associated_data: &[u8; 32], plaintext: &[u8]) -> (Ordinal, Header, Vec<u8>) {
    let (ord, header, ct) = send(&mut state.state, associated_data, plaintext);
    // Calculate h
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    hasher.update(&associated_data);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&ord.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&ord.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(&ct);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    // Add message to sent messages
    state.s.insert(Message{ordinal: ord, content: h});
    // Update num (ordinal) of state
    state.num = ord.clone();

    return (ord, header, ct);
}

pub fn arc_auth_send(state: &mut ArcState) -> (Ordinal, AuthenticationTag) {
    let at = AuthenticationTag{s: state.s.clone(), r: state.r.clone(), num: state.num.clone()};
    return (state.num.clone(), at);
}

pub fn arc_receive(state: &mut ArcState, associated_data: &[u8; 32], header: Header, ct: Vec<u8>) -> (bool, Ordinal, Vec<u8>) {
    let (acc, num, pt) = receive(&mut state.state, associated_data, header, &ct);
    if !acc {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new());
    }

    // Calculate h
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    hasher.update(&associated_data);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(&ct);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    if num <= state.max_num && !state.s_ack.contains(&Message { ordinal: num, content: h }) {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new());
    }

    state.r.insert(Message { ordinal: num, content: h });
    return (acc, num, pt);
}

pub fn arc_auth_receive(state: &mut ArcState, at: AuthenticationTag) -> (bool, Ordinal) {
    // Other party received a forgery
    if !at.r.is_subset(&state.s) {
        return (false, state.num);
    }
    let mut r_subset: HashSet<Message> = HashSet::new();
    for msg in state.r.iter() {
        if msg.ordinal <= at.num {
            r_subset.insert(msg.clone());
        }
    }
    // We received a forgery
    if !r_subset.is_subset(&at.s) {
        return (false, state.num);
    }

    // Update s_ack
    let _ = &at.s.iter().for_each(|elem| { state.s_ack.insert(elem.clone());});
    // Update max_num only if the at's ordinal is higher than our current
    if state.max_num < at.num {
        state.max_num = at.num;
    }
    return (true, at.num);
}

#[cfg(test)]
mod tests {
    use super::*;

    
}
