extern crate rc; 
use std::hash::{Hash, self};
use std::mem::size_of;
use std::{collections::HashSet, num};
use std::cmp::Ordering;
use hex_literal::hex;
use sha2::{Sha256, Sha512, Digest};


use rc::{State, Ordinal, Header, init_all, generate_dh, dh, send, receive};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use bytevec::{ByteEncodable, ByteDecodable};

pub struct RRC_State {
    pub state: State,
    pub hash_key: [u8;32],
    pub hash_key_prime: [u8;32], 
    pub S: HashSet<Message>,
    pub R: HashSet<Message>,
    pub S_ack: HashSet<Message>,
    pub max_num: Ordinal,
    pub security_level: Security
}
pub fn rrc_init_all(security_level: Security) -> (RRC_State, RRC_State) {
    // do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();

    let hash_key = dh(alice_hash_key, bob_hash_key.public);
    let hash_key_prime = dh(alice_hash_key_prime, bob_hash_key_prime.public);
    let (mut alice_rc_state, mut bob_rc_state) = init_all();
    let mut alice_state = RRC_State{state: alice_rc_state, hash_key: hash_key.to_bytes().clone(), hash_key_prime: hash_key_prime.to_bytes().clone(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: Ordinal { epoch: 0, index: 0 }, security_level: security_level.clone()};
    let mut bob_state = RRC_State{state: bob_rc_state, hash_key: hash_key.to_bytes(), hash_key_prime: hash_key_prime.to_bytes(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: Ordinal { epoch: 0, index: 0 }, security_level: security_level};

    return (alice_state, bob_state);
}
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Message {
    pub ordinal: Ordinal,
    //pub content: Vec<u8>
    pub content: [u8;32]
}

pub struct Ciphertext {
    pub ciphertext: Vec<u8>,
    pub S: HashSet<Message>,
    pub R: (HashSet<Ordinal>, [u8;32])
}

fn get_hash_msg_set(R: &HashSet<Message>, hash_key_prime: [u8; 32]) -> [u8; 32] {
    //let mut R_sorted = R.into_iter().collect::<Vec<Message>>();
    let mut R_sorted : Vec<Message> = Vec::new();
    for msg in R.iter() {
        R_sorted.push(msg.clone());
    }
    // Sort according to the Ordinal ordering
    let orders = vec![0, 1];
    R_sorted.sort_by(|a, b| {
        orders.iter().fold(Ordering::Equal, |acc, &field| {
            acc.then_with(|| {
                match field {
                    0 => a.ordinal.epoch.cmp(&b.ordinal.epoch),
                    _ => a.ordinal.index.cmp(&b.ordinal.index),
                }
            })
        })
    });
    let mut hasher = Sha256::new();
    let iterator = R_sorted.iter();  
    hasher.update(hash_key_prime);  
    for message in iterator {
        hasher.update(&message.content);
    }
    // read hash digest and consume hasher
    return hasher.finalize().try_into().unwrap();

}

fn get_hash_ordinal_set(R: &HashSet<Ordinal>) -> [u8; 32] {
    let mut R_sorted : Vec<Ordinal> = Vec::new();
    for ordinal in R.iter() {
        R_sorted.push(ordinal.clone());
    }
    //let mut R_sorted = R.into_iter().collect::<Vec<Ordinal>>();
    let orders = vec![0, 1];
    R_sorted.sort();
    let mut hasher = Sha256::new();
    let iterator = R_sorted.iter();  
    let usize_for_env = size_of::<usize>();
    let mut ordinal_as_bytes = [0u8; 2 * size_of::<usize>()];
    for ordinal in iterator {
        ordinal.epoch.to_be_bytes().clone_from_slice(&ordinal_as_bytes[0..usize_for_env]);
        ordinal.index.to_be_bytes().clone_from_slice(&ordinal_as_bytes[usize_for_env..2 * usize_for_env]);
        hasher.update(&ordinal_as_bytes);
    }
    return hasher.finalize().try_into().unwrap();

}


pub fn rrc_send(state: &mut RRC_State, associated_data: &[u8; 32], plaintext: &[u8]) -> (Ordinal, Ciphertext, Header) {
    let mut nums_prime: HashSet<Ordinal> = HashSet::new();
    let mut nums_prime_cpy: HashSet<Ordinal> = HashSet::new();
    for msg in state.R.iter() {
        nums_prime.insert(msg.ordinal);
        nums_prime_cpy.insert(msg.ordinal);
    }
    let mut R_prime: (HashSet<Ordinal>, [u8; 32]) = (nums_prime, get_hash_msg_set(&state.R, state.hash_key_prime));
    let mut associated_data_prime: [u8; 128] = [0;128];
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&state.S, [0;32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&R_prime.0));
    associated_data_prime[96..128].clone_from_slice(&R_prime.1);

    let sent: (Ordinal, Header, Vec<u8>) = send(&mut state.state, &associated_data_prime, plaintext);
    let ciphertext: Ciphertext = Ciphertext{ciphertext: sent.2, S: state.S.clone(), R: (nums_prime_cpy, R_prime.1.clone())};

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

pub fn rrc_receive(state: &mut RRC_State, associated_data: &[u8; 32], ct: &mut Ciphertext, header: Header) -> (bool, Ordinal, Vec<u8>) {
    let mut associated_data_prime: [u8; 128] = [0;128];
    associated_data_prime[0..32].clone_from_slice(associated_data);
    associated_data_prime[32..64].clone_from_slice(&get_hash_msg_set(&ct.S, [0;32]));
    associated_data_prime[64..96].clone_from_slice(&get_hash_ordinal_set(&ct.R.0));
    associated_data_prime[96..128].clone_from_slice(&ct.R.1);

    let (acc, num, pt) = receive(&mut state.state, &associated_data_prime, header, &ct.ciphertext);
    if !acc {
        println!("In here");
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
    for sent in ct.S.iter() {
        let conf = state.S_ack.insert(sent.clone());
        println!("element was added to s_ack is: {}", conf);
    }
    //&ct.S.iter().for_each(|elem| { state.S_ack.insert(elem.clone());});
    return (acc, num, pt);

} 

#[derive(Clone, PartialEq)]
pub enum Security {
    r_RID,
    s_RID,
    r_RID_and_s_RID
}

fn checks(state: &mut RRC_State, ct: &mut Ciphertext, h: &[u8; 32], num: Ordinal) -> bool {
    let mut s_bool: bool = false;
    let mut r_bool: bool = false;

    if state.security_level != Security::r_RID {
        let mut R_star: HashSet<Message> = HashSet::new();
        for num_prime in state.S.iter() {
            if ct.R.0.contains(&num_prime.ordinal) {
                R_star.insert(num_prime.clone());
            }
        }
        s_bool = get_hash_msg_set(&R_star, state.hash_key_prime) != ct.R.1;
        println!("s_bool = {}", s_bool);
        if state.security_level == Security::s_RID {
            return s_bool;
        }
    }
    let mut R_prime: HashSet<Message> = HashSet::new();
    for num_prime in state.R.iter() {
        if num_prime.ordinal <= num {
            R_prime.insert(num_prime.clone());
        }
    }
    r_bool = !ct.S.is_superset(&R_prime);
    r_bool = r_bool || ct.S.iter().fold(false, |acc, msg| acc || msg.ordinal >= num);

    println!("before if/else, r_bool = {}", r_bool);
    if num < state.max_num {
        r_bool = r_bool || !state.S_ack.contains(&Message { ordinal: num, content: h.to_owned()});
        r_bool = r_bool || !state.S_ack.is_superset(&ct.S);
        let mut S_ack_prime: HashSet<Message> = HashSet::new();
        println!("Before for loop, r_bool = {}", r_bool);
        for acked_msg in state.S_ack.iter() {
            if acked_msg.ordinal <= num {
                S_ack_prime.insert(acked_msg.clone());
            }
        }
        r_bool = r_bool || !ct.S.is_superset(&S_ack_prime);
    }
    else {
        state.max_num = num;
        println!("state s_ack contains = {}", state.S_ack.len());
        println!("max state num is = {}:{}",state.max_num.epoch, state.max_num.index);
        ct.S.difference(&state.S_ack).for_each(|elem| println!("looking at {}:{}", elem.ordinal.epoch, elem.ordinal.index));
        r_bool = r_bool || ct.S.difference(&state.S_ack).into_iter().fold(false, |acc, msg| acc || msg.ordinal < state.max_num);
        println!("after else, r_bool = {}", r_bool);
    }

    match state.security_level {
        Security::r_RID => r_bool,
        Security::r_RID_and_s_RID => r_bool || s_bool,
        Security::s_RID => return s_bool
        
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ordinal_ordering_works() {
        assert_eq!(true, Ordinal{epoch: 2, index:1} < Ordinal{epoch: 2, index:2});
        assert_eq!(true, Ordinal{epoch: 1, index:25} < Ordinal{epoch: 2, index:1});
        assert_eq!(Ordinal{epoch:10, index:5}, Ordinal{epoch:10, index:5});
    }

    #[test]
    fn send_and_receive_normal_functioning() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::r_RID_and_s_RID);
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
}
