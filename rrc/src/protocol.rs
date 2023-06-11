extern crate rc;
use blake2::Blake2s256;
use bytevec::{BVDecodeResult, BVEncodeResult, BVSize, ByteDecodable, ByteEncodable};
use mset_mu_hash::RistrettoHash;
use rand::SeedableRng;
use rand::{rngs::StdRng, RngCore};
use rc::{dh, generate_dh, init_all, receive, send, Header, Ordinal, State};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::hash::Hash;
use std::mem::size_of;
use x25519_dalek::PublicKey;

#[derive(Clone)]
pub struct RrcState {
    pub state: State,
    pub hash_key: [u8; 32],
    pub hash_key_prime: [u8; 32],
    pub s: HashSet<Message>,
    pub r: HashSet<Message>,
    pub s_ack: HashSet<Message>,
    pub max_num: Ordinal,
    pub security_level: Security,
}

#[derive(Clone)]
pub struct OptimizedSendRrcState {
    pub state: RrcState,
    pub incremental_hash: [u8; 32 + 2 * M_BYTES],
    pub hash_s: RistrettoHash<Sha512>,
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
    let (alice_rc_state, bob_rc_state) = init_all();
    let alice_state = RrcState {
        state: alice_rc_state,
        hash_key: hash_key.to_bytes().clone(),
        hash_key_prime: hash_key_prime.to_bytes().clone(),
        s: HashSet::new(),
        r: HashSet::new(),
        s_ack: HashSet::new(),
        max_num: Ordinal { epoch: 0, index: 0 },
        security_level: security_level.clone(),
    };
    let bob_state = RrcState {
        state: bob_rc_state,
        hash_key: hash_key.to_bytes(),
        hash_key_prime: hash_key_prime.to_bytes(),
        s: HashSet::new(),
        r: HashSet::new(),
        s_ack: HashSet::new(),
        max_num: Ordinal { epoch: 0, index: 0 },
        security_level: security_level,
    };

    return (alice_state, bob_state);
}

pub fn rrc_init_all_optimized_send(
    security_level: Security,
) -> (OptimizedSendRrcState, OptimizedSendRrcState) {
    // do key exchange for both hash keys
    let (rrc_alice, rrc_bob) = rrc_init_all(security_level);

    let alice_initial_hash =
        incremental_hash_fct_of_whole_set(&rrc_alice.r, &rrc_alice.hash_key_prime.clone());
    let bob_initial_hash =
        incremental_hash_fct_of_whole_set(&rrc_bob.r, &rrc_bob.hash_key_prime.clone());
    return (
        OptimizedSendRrcState {
            state: rrc_alice,
            incremental_hash: alice_initial_hash,
            hash_s: RistrettoHash::<Sha512>::default(),
            hash_ordinal_set: RistrettoHash::<Sha512>::default(),
            nums_prime: HashSet::new(),
        },
        OptimizedSendRrcState {
            state: rrc_bob,
            incremental_hash: bob_initial_hash,
            hash_s: RistrettoHash::<Sha512>::default(),
            hash_ordinal_set: RistrettoHash::<Sha512>::default(),
            nums_prime: HashSet::new(),
        },
    );
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Ord, PartialOrd)]
pub struct Message {
    pub ordinal: Ordinal,
    pub content: [u8; 32],
}

impl ByteEncodable for Message {
    /// Returns the total length of the byte buffer that is obtained through encode()
    fn get_size<Size>(&self) -> Option<Size>
    where
        Size: BVSize + ByteEncodable,
    {
        let usize_for_env = size_of::<usize>();
        return Some(BVSize::from_usize(32 + 2 * usize_for_env));
    }
    /// Returns a byte representation of the original data object
    fn encode<Size>(&self) -> BVEncodeResult<Vec<u8>>
    where
        Size: BVSize + ByteEncodable,
    {
        let mut bytes = [0u8; 32 + 2 * size_of::<usize>()];
        bytes[0..size_of::<usize>()].clone_from_slice(&self.ordinal.epoch.to_be_bytes());
        bytes[size_of::<usize>()..2 * size_of::<usize>()]
            .copy_from_slice(&self.ordinal.index.to_be_bytes());
        bytes[2 * size_of::<usize>()..2 * size_of::<usize>() + 32].copy_from_slice(&self.content);

        return Ok(bytes.to_vec());
    }
}

impl ByteDecodable for Message {
    /// Returns an instance of `Self` obtained from the deserialization of the provided byte buffer.
    fn decode<Size>(bytes: &[u8]) -> BVDecodeResult<Self>
    where
        Size: BVSize + ByteDecodable,
    {
        let ordinal_epoch = usize::from_be_bytes(bytes[0..size_of::<usize>()].try_into().unwrap());
        let ordinal_index = usize::from_be_bytes(
            bytes[size_of::<usize>()..2 * size_of::<usize>()]
                .try_into()
                .unwrap(),
        );
        let content: [u8; 32] = bytes[2 * size_of::<usize>()..2 * size_of::<usize>() + 32]
            .try_into()
            .unwrap();

        return Ok(Message {
            ordinal: Ordinal {
                epoch: ordinal_epoch,
                index: ordinal_index,
            },
            content: content.try_into().unwrap(),
        });
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    pub ciphertext: Vec<u8>,
    pub s: HashSet<Message>,
    pub r: (HashSet<Ordinal>, [u8; 32]),
}

#[derive(Clone)]
pub struct OptimizedSendCiphertext {
    pub ciphertext: Vec<u8>,
    pub s: HashSet<Message>,
    pub r: (HashSet<Ordinal>, [u8; 32 + 2 * M_BYTES]),
}

pub(crate) fn get_hash_msg_set(r: &HashSet<Message>, hash_key_prime: [u8; 32]) -> [u8; 32] {
    //let mut R_sorted = R.into_iter().collect::<Vec<Message>>();
    let mut r_sorted: BTreeSet<Message> = BTreeSet::new();
    for msg in r.iter() {
        r_sorted.insert(msg.clone());
    }
    let mut hasher = Sha256::new();
    let iterator = r_sorted.iter();
    hasher.update(hash_key_prime);
    for message in iterator {
        let usize_for_env = size_of::<usize>();
        let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&message.ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env]
            .clone_from_slice(&message.ordinal.index.to_be_bytes());
        hasher.update(&ordinal_as_bytes);
        hasher.update(&ordinal_as_bytes);
        hasher.update(&message.content);
    }
    // read hash digest and consume hasher
    return hasher.finalize().try_into().unwrap();
}

fn opti_get_hash_msg_set(r: &HashSet<Message>) -> [u8; 32] {
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    let usize_for_env = size_of::<usize>();

    for message in r.iter() {
        let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&message.ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env]
            .clone_from_slice(&message.ordinal.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
        multiset_hash.add(&message.content, 1);
    }
    return multiset_hash.finalize();
}

fn opti_get_hash_ordinal_set(r: &HashSet<Ordinal>) -> [u8; 32] {
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    let mut multiset_hash = RistrettoHash::<Sha512>::default();
    for ord in r.iter() {
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ord.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env]
            .clone_from_slice(&ord.index.to_be_bytes());
        multiset_hash.add(&ordinal_as_bytes, 1);
    }

    return multiset_hash.finalize();
}

pub(crate) fn get_hash_ordinal_set(r: &HashSet<Ordinal>) -> [u8; 32] {
    let mut r_sorted: BTreeSet<Ordinal> = BTreeSet::new();
    for ordinal in r.iter() {
        r_sorted.insert(ordinal.clone());
    }
    let mut hasher = Sha256::new();
    let iterator = r_sorted.iter();
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    for ordinal in iterator {
        ordinal_as_bytes[0..usize_for_env].clone_from_slice(&ordinal.epoch.to_be_bytes());
        ordinal_as_bytes[usize_for_env..2 * usize_for_env]
            .clone_from_slice(&ordinal.index.to_be_bytes());
        hasher.update(&ordinal_as_bytes);
    }
    return hasher.finalize().try_into().unwrap();
}

pub fn rrc_send(
    state: &mut RrcState,
    associated_data: &[u8; 32],
    plaintext: &[u8],
) -> (Ordinal, Ciphertext, Header) {
    let mut nums_prime: HashSet<Ordinal> = HashSet::new();
    for msg in state.r.iter() {
        nums_prime.insert(msg.ordinal);
    }
    let r_prime: (HashSet<Ordinal>, [u8; 32]) = (
        nums_prime.clone(),
        get_hash_msg_set(&state.r, state.hash_key_prime),
    );
    let mut associated_data_prime: [u8; 128] = [0; 128];
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&state.s, [0; 32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&r_prime.0));
    associated_data_prime[96..128].clone_from_slice(&r_prime.1);

    let sent: (Ordinal, Header, Vec<u8>) =
        send(&mut state.state, &associated_data_prime, plaintext);
    let ciphertext: Ciphertext = Ciphertext {
        ciphertext: sent.2,
        s: state.s.clone(),
        r: (nums_prime, r_prime.1.clone()),
    };

    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&sent.0.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2]
        .clone_from_slice(&sent.0.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ciphertext.ciphertext);
    hasher.update(get_hash_msg_set(&ciphertext.s, [0; 32]));
    hasher.update(get_hash_ordinal_set(&ciphertext.r.0));
    hasher.update(&ciphertext.r.1);
    let h: [u8; 32] = hasher.finalize().try_into().unwrap();
    state.s.insert(Message {
        ordinal: sent.0,
        content: h,
    });

    return (sent.0, ciphertext, sent.1);
}

pub fn rrc_receive(
    state: &mut RrcState,
    associated_data: &[u8; 32],
    ct: &mut Ciphertext,
    header: Header,
) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 128] = [0; 128];

    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&ct.s, [0; 32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&ct.r.0));
    associated_data_prime[96..128].clone_from_slice(&ct.r.1);

    let (acc, num, pt) = receive(
        &mut state.state,
        &associated_data_prime,
        header,
        &ct.ciphertext,
    );

    if !acc {
        return (false, num, Vec::new());
    }
    let mut hasher = Sha256::new();
    hasher.update(&state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2]
        .clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.ciphertext);
    hasher.update(get_hash_msg_set(&ct.s, [0; 32]));
    hasher.update(get_hash_ordinal_set(&ct.r.0));
    hasher.update(&ct.r.1);
    let h: [u8; 32] = hasher.finalize().try_into().unwrap();
    if checks(state, ct, &h, num) {
        return (false, num, Vec::new());
    }

    state.r.insert(Message {
        ordinal: num,
        content: h,
    });
    //state.S_ack.insert(Message { ordinal:Ordinal { epoch: header.epoch, index: header.msg_nbr }, content: h });
    let _ = &ct.s.iter().for_each(|elem| {
        state.s_ack.insert(elem.clone());
    });
    return (acc, num, pt);
}

#[derive(Clone, PartialEq)]
pub enum Security {
    RRid,
    SRid,
    RRidAndSRid,
}

fn checks(state: &mut RrcState, ct: &mut Ciphertext, h: &[u8; 32], num: Ordinal) -> bool {
    let mut s_bool: bool = false;

    if state.security_level != Security::RRid {
        let mut r_star: HashSet<Message> = HashSet::new();
        for num_prime in state.s.iter() {
            if ct.r.0.contains(&num_prime.ordinal) {
                r_star.insert(num_prime.clone());
            }
        }
        s_bool = get_hash_msg_set(&r_star, state.hash_key_prime) != ct.r.1;
        if state.security_level == Security::SRid {
            return s_bool;
        }
    }
    let mut r_prime: HashSet<Message> = HashSet::new();
    for num_prime in state.r.iter() {
        if num_prime.ordinal <= num {
            r_prime.insert(num_prime.clone());
        }
    }
    let mut r_bool = !r_prime.is_subset(&ct.s);
    r_bool = r_bool
        || ct
            .s
            .iter()
            .fold(false, |acc, msg| acc || msg.ordinal >= num);
    if num < state.max_num {
        r_bool = r_bool
            || !state.s_ack.contains(&Message {
                ordinal: num,
                content: h.to_owned(),
            });
        r_bool = r_bool || !ct.s.is_subset(&state.s_ack);
        let mut s_ack_prime: HashSet<Message> = HashSet::new();
        for acked_msg in state.s_ack.iter() {
            if acked_msg.ordinal < num {
                s_ack_prime.insert(acked_msg.clone());
            }
        }
        r_bool = r_bool || !s_ack_prime.is_subset(&ct.s);
    } else {
        state.max_num = num;
        r_bool = r_bool
            || state
                .s_ack
                .difference(&ct.s)
                .into_iter()
                .fold(false, |acc, msg| acc || msg.ordinal < state.max_num); // -> fix w.r.t paper
    }

    match state.security_level {
        Security::RRid => return r_bool,
        Security::RRidAndSRid => return r_bool || s_bool,
        Security::SRid => return s_bool,
    }
}

fn optimized_checks(
    state: &mut RrcState,
    ct: &mut OptimizedSendCiphertext,
    h: &[u8; 32],
    num: Ordinal,
) -> bool {
    let mut s_bool: bool = false;

    if state.security_level != Security::RRid {
        let mut r_star: HashSet<Message> = HashSet::new();
        for num_prime in state.s.iter() {
            if ct.r.0.contains(&num_prime.ordinal) {
                r_star.insert(num_prime.clone());
            }
        }
        s_bool = !incremental_hash_sets_are_equal(
            incremental_hash_fct_of_whole_set(&r_star, &state.hash_key_prime),
            ct.r.1,
            &state.hash_key_prime,
        );
        if state.security_level == Security::SRid {
            return s_bool;
        }
    }
    let mut r_prime: HashSet<Message> = HashSet::new();
    for num_prime in state.r.iter() {
        if num_prime.ordinal <= num {
            r_prime.insert(num_prime.clone());
        }
    }
    let mut r_bool = !r_prime.is_subset(&ct.s);
    r_bool = r_bool
        || ct
            .s
            .iter()
            .fold(false, |acc, msg| acc || msg.ordinal >= num);
    if num < state.max_num {
        r_bool = r_bool
            || !state.s_ack.contains(&Message {
                ordinal: num,
                content: h.to_owned(),
            });
        r_bool = r_bool || !ct.s.is_subset(&state.s_ack);
        let mut s_ack_prime: HashSet<Message> = HashSet::new();
        for acked_msg in state.s_ack.iter() {
            if acked_msg.ordinal < num {
                s_ack_prime.insert(acked_msg.clone());
            }
        }
        r_bool = r_bool || !s_ack_prime.is_subset(&ct.s);
    } else {
        state.max_num = num;
        r_bool = r_bool
            || state
                .s_ack
                .difference(&ct.s)
                .into_iter()
                .fold(false, |acc, msg| acc || msg.ordinal < state.max_num);
    }

    match state.security_level {
        Security::RRid => r_bool,
        Security::RRidAndSRid => r_bool || s_bool,
        Security::SRid => return s_bool,
    }
}

/* Generates a 256bit random nonce used for the incremental hash function
 * Hash function 0 is SHA256, Hash function 1 is Blake2s256.
 */
fn generate_nonce() -> [u8; M_BYTES] {
    let mut nonce = [0u8; M_BYTES];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut nonce);
    return nonce;
}

const M: usize = 256 + 24; // We support 2^24 messages with hashes of 256 bits
const M_BYTES: usize = M / 8;
/*
 * Hash function 0 is SHA256, Hash function 1 is Blake2s256.
 * Generates a triple [h, c, r] as stated in https://people.csail.mit.edu/devadas/pubs/mhashes.pdf
 * Implements the Mset-XOR-Hash.
 */
pub(crate) fn incremental_hash_fct_of_whole_set(
    r: &HashSet<Message>,
    hash_key_prime: &[u8; 32],
) -> [u8; 32 + 2 * M_BYTES] {
    let mut hash: [u8; 32 + 2 * M_BYTES] = [0; 32 + 2 * M_BYTES];
    let nonce = generate_nonce();
    hash[32 + M_BYTES..32 + 2 * M_BYTES].clone_from_slice(&nonce);

    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&nonce);
    let mut h: [u8; 32] = hasher.finalize().try_into().unwrap();

    // Order in which messages are iterated isn't relevant since xor is commutative.
    for msg in r.iter() {
        let hashed_msg = hash_msg_w_blake2(msg, &hash_key_prime);
        let xored: Vec<u8> = h
            .iter()
            .zip(hashed_msg.iter())
            .map(|(&byte1, &byte2)| byte1 ^ byte2)
            .collect();
        h = xored.try_into().unwrap();
    }

    hash[0..32].clone_from_slice(&h);
    let usize_for_env = size_of::<usize>();
    // Here the has fct protocol says to take modulo 2^m but usize we already have modulo usize MAX_VALUE.
    let nbr_elems_in_r_bytes = (r.len()).to_be_bytes();
    let mut correct_size_nbr_elems = [0; M_BYTES];
    correct_size_nbr_elems[M_BYTES - usize_for_env..M_BYTES]
        .clone_from_slice(&nbr_elems_in_r_bytes);
    hash[32..32 + M_BYTES].clone_from_slice(&correct_size_nbr_elems);

    return hash;
}

fn hash_msg_w_blake2(msg: &Message, hash_key_prime: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(&hash_key_prime);
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env]
        .clone_from_slice(&msg.ordinal.index.to_be_bytes());
    hasher.update(&ordinal_as_bytes);
    hasher.update(&msg.content);
    return hasher.finalize().try_into().unwrap();
}

/*Hash function 0 is SHA256, Hash function 1 is Blake2s256 */
pub(crate) fn incremental_hash_sets_are_equal(
    hash1: [u8; 32 + 2 * M_BYTES],
    hash2: [u8; 32 + 2 * M_BYTES],
    hash_key_prime: &[u8; 32],
) -> bool {
    // define hash of H(0,r)
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&hash1[32 + M_BYTES..32 + 2 * M_BYTES]);
    let h_0_r1: [u8; 32] = hasher.finalize().try_into().unwrap();
    let xored1: Vec<u8> = h_0_r1
        .iter()
        .zip(hash1[0..32].iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect();

    // define hash of H(0,r')
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&hash2[32 + M_BYTES..32 + 2 * M_BYTES]);
    let h_0_r2: [u8; 32] = hasher.finalize().try_into().unwrap();
    let xored2: Vec<u8> = h_0_r2
        .iter()
        .zip(hash2[0..32].iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect();
    // check if hash1[h] xor hash_r == hash2[h] xor hash_r'
    // check if hash1[c] == hash2[c]
    return xored1 == xored2 && hash1[32..32 + M_BYTES] == hash2[32..32 + M_BYTES];
}

pub(crate) fn update_incremental_hash_set(
    incremental_hash: &mut [u8; 32 + 2 * M_BYTES],
    msg: Message,
    hash_key_prime: &[u8; 32],
) -> [u8; 32 + 2 * M_BYTES] {
    let mut new_hash: [u8; 32 + 2 * M_BYTES] = [0; 32 + 2 * M_BYTES];
    // Update the first element in the tuple
    let mut hasher = Sha256::new();
    hasher.update(&hash_key_prime);
    hasher.update(&incremental_hash[32 + M_BYTES..32 + 2 * M_BYTES]);
    let h_0_r: [u8; 32] = hasher.finalize().try_into().unwrap();
    let hash_without_nonce_hash: Vec<u8> = h_0_r
        .iter()
        .zip(incremental_hash[0..32].iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect();
    let msg_hash = hash_msg_w_blake2(&msg, hash_key_prime);
    let new_h_without_xor_nonce: Vec<u8> = msg_hash
        .iter()
        .zip(hash_without_nonce_hash.iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect();

    // Update the second element (cardinality of set)
    let usize_for_env = size_of::<usize>();
    let mut cardinality_r: usize = usize::from_be_bytes(
        incremental_hash[32 + M_BYTES - usize_for_env..32 + M_BYTES]
            .try_into()
            .unwrap(),
    );
    cardinality_r += 1;
    let nbr_elems_in_r_bytes = (cardinality_r).to_be_bytes();
    let mut correct_size_nbr_elems = [0; M_BYTES];
    correct_size_nbr_elems[M_BYTES - usize_for_env..M_BYTES]
        .clone_from_slice(&nbr_elems_in_r_bytes);
    new_hash[32..32 + M_BYTES].clone_from_slice(&correct_size_nbr_elems);

    let nonce = generate_nonce();
    new_hash[32 + M_BYTES..32 + 2 * M_BYTES].clone_from_slice(&nonce);
    hasher = Sha256::new();
    hasher.update(hash_key_prime);
    hasher.update(nonce);
    let hash_nonce: [u8; 32] = hasher.finalize().try_into().unwrap();
    let new_h: Vec<u8> = new_h_without_xor_nonce
        .iter()
        .zip(hash_nonce.iter())
        .map(|(&byte1, &byte2)| byte1 ^ byte2)
        .collect();
    new_hash[0..32].clone_from_slice(&new_h);

    return new_hash;
}

pub fn optimized_rrc_send(
    state: &mut OptimizedSendRrcState,
    associated_data: &[u8; 32],
    plaintext: &[u8],
) -> (Ordinal, OptimizedSendCiphertext, Header) {
    let r_prime: (HashSet<Ordinal>, [u8; 32 + 2 * M_BYTES]) =
        (state.nums_prime.clone(), state.incremental_hash);
    let mut associated_data_prime: [u8; 128 + 2 * M_BYTES] = [0; 128 + 2 * M_BYTES];
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&state.hash_s.clone().finalize());
    associated_data_prime[64..96].clone_from_slice(&state.hash_ordinal_set.clone().finalize());
    associated_data_prime[96..128 + 2 * M_BYTES].clone_from_slice(&r_prime.1);

    let sent: (Ordinal, Header, Vec<u8>) =
        send(&mut state.state.state, &associated_data_prime, plaintext);
    let ciphertext: OptimizedSendCiphertext = OptimizedSendCiphertext {
        ciphertext: sent.2,
        s: state.state.s.clone(),
        r: (state.nums_prime.clone(), r_prime.1.clone()),
    };

    let mut hasher = Sha256::new();
    hasher.update(&state.state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&sent.0.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2]
        .clone_from_slice(&sent.0.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ciphertext.ciphertext);
    hasher.update(&state.hash_s.clone().finalize());
    hasher.update(state.hash_ordinal_set.clone().finalize());
    hasher.update(&ciphertext.r.1);
    let h: [u8; 32] = hasher.finalize().try_into().unwrap();

    let new_msg = Message {
        ordinal: sent.0,
        content: h,
    };
    state.state.s.insert(new_msg.clone());

    // Update the hash of all sent messages using the new message
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&new_msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env]
        .clone_from_slice(&new_msg.ordinal.index.to_be_bytes());
    state.hash_s.add(&ordinal_as_bytes, 1);
    state.hash_s.add(&new_msg.content, 1);

    return (sent.0, ciphertext, sent.1);
}

pub fn optimized_rrc_receive(
    state: &mut OptimizedSendRrcState,
    associated_data: &[u8; 32],
    ct: &mut OptimizedSendCiphertext,
    header: Header,
) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 128 + 2 * M_BYTES] = [0; 128 + 2 * M_BYTES];

    let hash_sent_ct = opti_get_hash_msg_set(&ct.s);
    let ordinal_set_hash = opti_get_hash_ordinal_set(&ct.r.0);

    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&hash_sent_ct);
    associated_data_prime[64..96].clone_from_slice(&ordinal_set_hash);
    associated_data_prime[96..128 + 2 * M_BYTES].clone_from_slice(&ct.r.1);

    let (acc, num, pt) = receive(
        &mut state.state.state,
        &associated_data_prime,
        header,
        &ct.ciphertext,
    );

    if !acc {
        return (false, num, Vec::new());
    }
    let mut hasher = Sha256::new();
    hasher.update(&state.state.hash_key);
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    ordinal_as_bytes[size_of::<usize>()..size_of::<usize>() * 2]
        .clone_from_slice(&num.index.to_be_bytes());
    hasher.update(ordinal_as_bytes);
    hasher.update(associated_data);
    hasher.update(&ct.ciphertext);
    hasher.update(&hash_sent_ct);
    hasher.update(ordinal_set_hash);
    hasher.update(&ct.r.1);
    let h: [u8; 32] = hasher.finalize().try_into().unwrap();
    if optimized_checks(&mut state.state, ct, &h, num) {
        return (false, num, Vec::new());
    }

    let msg = Message {
        ordinal: num,
        content: h,
    };
    state.state.r.insert(msg.clone());
    state.nums_prime.insert(msg.ordinal.clone());

    // Update hash of ordinals you've received using multiset hash
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    ordinal_as_bytes[0..usize_for_env].clone_from_slice(&msg.ordinal.epoch.to_be_bytes());
    ordinal_as_bytes[usize_for_env..2 * usize_for_env]
        .clone_from_slice(&msg.ordinal.index.to_be_bytes());
    state.hash_ordinal_set.add(&ordinal_as_bytes, 1);
    state.incremental_hash = update_incremental_hash_set(
        &mut state.incremental_hash,
        msg,
        &state.state.hash_key_prime,
    );
    let _ = &ct.s.iter().for_each(|elem| {
        state.state.s_ack.insert(elem.clone());
    });
    return (acc, num, pt);
}

pub fn send_bytes(state: &mut RrcState, associated_data: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // 1. Call send to obtain encrypted message as objects
    let (num, ct, header) = rrc_send(state, associated_data, plaintext);
    // 2. Get size of each individual element we will encode
    // 2.1 Everything for the ciphertext object
    let msg_ct_len = ct.ciphertext.len();
    let ct_s_as_bytes = ct.s.encode::<u32>().unwrap();
    let s_len = ct_s_as_bytes.len();
    let ct_r_ord_set_as_bytes = ct.r.0.encode::<u32>().unwrap();
    let r_ord_set_len = ct_r_ord_set_as_bytes.len();
    let ct_len = msg_ct_len + s_len + r_ord_set_len + 32; // + 32 bytes for r_1
                                                          // 2.2 Everything for the header
    let dh_pk_len: usize = header.dh_ratchet_key.to_bytes().len();
    let header_len: usize = dh_pk_len + 3 * size_of::<usize>(); // + 3 * usize
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
    bytes[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()]
        .clone_from_slice(&header.msg_nbr.to_be_bytes());
    bytes[32 + 2 * size_of::<usize>()..header_len].clone_from_slice(&header.epoch.to_be_bytes());
    // 4.2 The ordinal: epoch || index
    bytes[header_len..header_len + size_of::<usize>()].clone_from_slice(&num.epoch.to_be_bytes());
    bytes[header_len + size_of::<usize>()..header_len + ordinal_len]
        .clone_from_slice(&num.index.to_be_bytes());
    // 4.3 The ciphertext: ct_len || s_len || r_0_len || ct || s || r_0 || r_1
    bytes[header_len + ordinal_len..header_len + ordinal_len + size_of::<usize>()]
        .clone_from_slice(&msg_ct_len.to_be_bytes());
    bytes[header_len + ordinal_len + size_of::<usize>()
        ..header_len + ordinal_len + 2 * size_of::<usize>()]
        .clone_from_slice(&s_len.to_be_bytes());
    bytes[header_len + ordinal_len + 2 * size_of::<usize>()
        ..header_len + ordinal_len + metadata_len]
        .clone_from_slice(&r_ord_set_len.to_be_bytes());
    bytes[header_len + ordinal_len + metadata_len
        ..header_len + ordinal_len + metadata_len + msg_ct_len]
        .clone_from_slice(&ct.ciphertext);
    bytes[header_len + ordinal_len + metadata_len + msg_ct_len
        ..header_len + ordinal_len + metadata_len + msg_ct_len + s_len]
        .clone_from_slice(&ct_s_as_bytes);
    bytes[header_len + ordinal_len + metadata_len + msg_ct_len + s_len
        ..header_len + ordinal_len + metadata_len + msg_ct_len + s_len + r_ord_set_len]
        .clone_from_slice(&ct_r_ord_set_as_bytes);
    bytes[total_len - 32..total_len].clone_from_slice(&ct.r.1);

    return bytes;
}

pub fn receive_bytes(
    payload: &[u8],
    state: &mut RrcState,
    associated_data: &[u8; 32],
) -> (bool, Ordinal, Vec<u8>) {
    // 1. Decode header
    let mut pk_bytes = [0u8; 32];
    pk_bytes.clone_from_slice(&payload[0..32]);
    let header = Header {
        dh_ratchet_key: PublicKey::from(pk_bytes),
        prev_chain_len: usize::from_be_bytes(
            payload[32..32 + size_of::<usize>()].try_into().unwrap(),
        ),
        msg_nbr: usize::from_be_bytes(
            payload[32 + size_of::<usize>()..32 + 2 * size_of::<usize>()]
                .try_into()
                .unwrap(),
        ),
        epoch: usize::from_be_bytes(
            payload[32 + 2 * size_of::<usize>()..32 + 3 * size_of::<usize>()]
                .try_into()
                .unwrap(),
        ),
    };
    // 2. Decode ciphertext
    let ct_meta_offset = 32 + 5 * size_of::<usize>();
    let ct_len = usize::from_be_bytes(
        payload[ct_meta_offset..ct_meta_offset + size_of::<usize>()]
            .try_into()
            .unwrap(),
    );
    let s_len = usize::from_be_bytes(
        payload[ct_meta_offset + size_of::<usize>()..ct_meta_offset + 2 * size_of::<usize>()]
            .try_into()
            .unwrap(),
    );
    let r_0_len = usize::from_be_bytes(
        payload[ct_meta_offset + 2 * size_of::<usize>()..ct_meta_offset + 3 * size_of::<usize>()]
            .try_into()
            .unwrap(),
    );

    let ct_offset = ct_meta_offset + 3 * size_of::<usize>();
    let s: HashSet<Message> =
        HashSet::decode::<u32>(&payload[ct_offset + ct_len..ct_offset + ct_len + s_len]).unwrap();
    let r_0: HashSet<Ordinal> = HashSet::decode::<u32>(
        &payload[ct_offset + ct_len + s_len..ct_offset + ct_len + s_len + r_0_len],
    )
    .unwrap();
    let mut r_1 = [0u8; 32];
    r_1.clone_from_slice(&payload[ct_offset + ct_len + s_len + r_0_len..payload.len()]);
    let mut ct = Ciphertext {
        ciphertext: payload[ct_offset..ct_offset + ct_len].to_vec(),
        s,
        r: (r_0, r_1),
    };
    return rrc_receive(state, associated_data, &mut ct, header);
}
