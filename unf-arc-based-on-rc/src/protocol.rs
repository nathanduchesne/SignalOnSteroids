use std::{collections::HashSet, mem::size_of, hash::Hash};
use rc::*;
use sha2::{Sha256, Digest};

/// We use the same message structure as in the rest of the project but adjust it to use ArcOrdinals rather than usual ordinals.
#[derive(Hash, Eq, PartialEq, Debug, Clone, Ord, PartialOrd)]
pub struct Message {
    pub ordinal: ArcOrdinal,
    pub content: [u8;32]
}

#[derive(Clone)]
pub struct ArcState {
    state: State,
    hash_key: [u8; 32],
    s: HashSet<Message>,
    r: HashSet<Message>,
    s_ack: HashSet<Message>,
    pub num: ArcOrdinal,
    max_num: ArcOrdinal
}

#[derive(Clone)]
pub struct AuthenticationTag {
    s: HashSet<Message>,
    r: HashSet<Message>,
    pub num: ArcOrdinal
}

/// These ordinals are identical to the Ordinals presented in Signal and used in the rest of the project apart from one slight difference:
/// 
/// - they use signed integers rather than unsigned integers
/// 
/// This is done to account for the fact that one comparison in arc_receive() checks if num <= max_num and if this message has already been acked.
/// This check is crucial to avoid forgeries but fails with unsigned integers upon receiving the first message. To deal with this, we provide an easy
/// fix by giving max_num a value it will never have and that is smaller than any possible real ordinal.
#[derive(Clone, Hash, Eq, PartialEq, Debug, Ord, PartialOrd, Copy)]
pub struct ArcOrdinal {
    pub epoch: i32,
    pub index: i32
}

/// Initialize the states for both parties
pub fn arc_init() -> (ArcState, ArcState) {
    let (alice_rc_state, bob_rc_state) = init_all();

    // Perform key exchange for the hash key
    let alice_hash_key = generate_dh();
    let bob_hash_key = generate_dh();
    let hash_key = dh(alice_hash_key, bob_hash_key.public);

    let alice_state = ArcState{state: alice_rc_state, hash_key: hash_key.to_bytes().clone(), s: HashSet::new(), r: HashSet::new(), s_ack: HashSet::new(), num: ArcOrdinal { epoch: 0, index: 0 }, max_num: ArcOrdinal { epoch: 0, index: -1 }};
    let bob_state = ArcState{state: bob_rc_state, hash_key: hash_key.to_bytes(), s: HashSet::new(), r: HashSet::new(), s_ack: HashSet::new(), num: ArcOrdinal { epoch: 0, index: 0 }, max_num: ArcOrdinal { epoch: 0, index: -1 }};

    return (alice_state, bob_state);
}

/// Send an encrypted message to the other party with UNF-Security 
pub fn arc_send(state: &mut ArcState, associated_data: &[u8; 32], plaintext: &[u8]) -> (ArcOrdinal, Header, Vec<u8>) {
    let (ord, header, ct) = send(&mut state.state, associated_data, plaintext);
    let ord = ArcOrdinal{epoch: ord.epoch.try_into().unwrap(), index: ord.index.try_into().unwrap()};

    // Calculate the hashed version of the message with the hash key, ordinal and associated data
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    hasher.update(&associated_data);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<i32>()];
    ordinal_as_bytes[0..size_of::<i32>()].clone_from_slice(&ord.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<i32>()..size_of::<i32>() * 2].clone_from_slice(&ord.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(&ct);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    // Add message to sent messages
    state.s.insert(Message{ordinal: ArcOrdinal { epoch: ord.epoch.try_into().unwrap(), index: ord.index.try_into().unwrap() }, content: h});
    // Update num (ordinal) of state
    state.num = ArcOrdinal { epoch: ord.epoch.try_into().unwrap(), index: ord.index.try_into().unwrap() };

    return (ArcOrdinal { epoch: ord.epoch.try_into().unwrap(), index: ord.index.try_into().unwrap() }, header, ct);
}

/// Send an authentication tag to the other party for out-of-bands verification
pub fn arc_auth_send(state: &mut ArcState) -> (ArcOrdinal, AuthenticationTag) {
    let at = AuthenticationTag{s: state.s.clone(), r: state.r.clone(), num: state.num.clone()};
    return (state.num.clone(), at);
}

/// Receive an encrypted message from the other party with UNF-Security
pub fn arc_receive(state: &mut ArcState, associated_data: &[u8; 32], header: Header, ct: Vec<u8>) -> (bool, ArcOrdinal, Vec<u8>) {
    let (acc, num, pt) = receive(&mut state.state, associated_data, header, &ct);
    if !acc {
        return (false, ArcOrdinal{epoch: 0, index: 0}, Vec::new());
    }
    let num = ArcOrdinal{epoch: num.epoch.try_into().unwrap(), index: num.index.try_into().unwrap()};

    // Calculate the hashed version of the message with the hash key, ordinal and associated data
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    hasher.update(&associated_data);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<i32>()];
    ordinal_as_bytes[0..size_of::<i32>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<i32>()..size_of::<i32>() * 2].clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(&ct);
    let h: [u8;32] = hasher.finalize().try_into().unwrap();

    // Check that if you receive an out of order message (num <= max_num) means we have authenticated messages up to max_num
    // then you must have necessarily acked it when receiving it in the authentication tag
    if num <= state.max_num && !state.s_ack.contains(&Message { ordinal: num, content: h }) {
        return (false, ArcOrdinal{epoch: 0, index: 0}, Vec::new());
    }

    state.r.insert(Message { ordinal: num, content: h });
    return (acc, num, pt);
}

/// Receive an authentication tag from the other party for out-of-bands verification
pub fn arc_auth_receive(state: &mut ArcState, at: AuthenticationTag) -> (bool, ArcOrdinal) {
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

    // Update max_num only if it increases the number of messages that have been authenticated
    if state.max_num < at.num {
        state.max_num = at.num;
    }
    return (true, at.num);
}