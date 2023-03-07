extern crate rc; 
use std::collections::HashSet;
use std::cmp::Ordering;
use hex_literal::hex;
use sha2::{Sha256, Sha512, Digest};


use rc::{State, Ordinal, Header, init_all, generate_dh, dh, send};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use bytevec::{ByteEncodable, ByteDecodable};

pub struct RRC_State {
    pub state: State,
    pub hash_key: [u8;32],
    pub hash_key_prime: [u8;32], 
    pub S: HashSet<Message>,
    pub R: HashSet<Message>,
    pub S_ack: HashSet<Message>,
    pub max_num: u32
}
pub fn rrc_init_all() -> (RRC_State, RRC_State) {
    // do key exchange for both hash keys
    let alice_hash_key = generate_dh();
    let alice_hash_key_prime = generate_dh(); 
    let bob_hash_key = generate_dh();
    let bob_hash_key_prime = generate_dh();

    let hash_key = dh(alice_hash_key, bob_hash_key.public);
    let hash_key_prime = dh(alice_hash_key_prime, bob_hash_key_prime.public);
    let (mut alice_rc_state, mut bob_rc_state) = init_all();
    let mut alice_state = RRC_State{state: alice_rc_state, hash_key: hash_key.to_bytes().clone(), hash_key_prime: hash_key_prime.to_bytes().clone(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: 0};
    let mut bob_state = RRC_State{state: bob_rc_state, hash_key: hash_key.to_bytes(), hash_key_prime: hash_key_prime.to_bytes(), S: HashSet::new(), R: HashSet::new(), S_ack: HashSet::new(), max_num: 0};

    return (alice_state, bob_state);
}
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct Message {
    pub ordinal: Ordinal,
    pub content: Vec<u8>
}

pub struct Ciphertext {
    pub ciphertext: Vec<u8>,
    pub S: HashSet<Message>,
    pub R: HashSet<Message>
}

fn get_hash_r(R: HashSet<Message>, hash_key_prime: [u8; 32]) -> [u8; 32] {
    let mut R_sorted = R.into_iter().collect::<Vec<Message>>();
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


pub fn rrc_send(state: &mut RRC_State, associated_data: &[u8], plaintext: &[u8]) -> () {
    // Get nums'
    // Get hash of R 
    

    let(num, header, ciphertext) = send(&mut state.state, associated_data, plaintext);
}
pub fn add(left: usize, right: usize) -> usize {
    left + right
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
    fn get_hash_of_set_works() {
        let mut first_set: HashSet<Message> = HashSet::new();
        let mut second_set: HashSet<Message> = HashSet::new();

        let first_msg = Message{content: b"premier".to_vec(), ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: b"deuxieme".to_vec(), ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: b"troisieme".to_vec(), ordinal: Ordinal { epoch: 5, index: 0 }};

        first_set.insert(first_msg);
        first_set.insert(second_msg);
        first_set.insert(third_msg);

        let first_msg = Message{content: b"premier".to_vec(), ordinal: Ordinal { epoch: 3, index: 17 }};
        let second_msg = Message{content: b"deuxieme".to_vec(), ordinal: Ordinal { epoch: 3, index: 19 }};
        let third_msg = Message{content: b"troisieme".to_vec(), ordinal: Ordinal { epoch: 5, index: 0 }};

        second_set.insert(third_msg);
        second_set.insert(first_msg);
        second_set.insert(second_msg);

        let hash_key_prime: [u8;32] = [0;32];

        assert_eq!(get_hash_r(first_set, hash_key_prime), get_hash_r(second_set, hash_key_prime));
        
    }
}
