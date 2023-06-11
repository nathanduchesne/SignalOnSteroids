#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use std::{fs::File, io::Write, time::SystemTime};
    use crate::{init_all, protocol::{generate_dh, dh, encrypt, decrypt, State, ratchet_encrypt, ratchet_decrypt, send, receive, Header, MAX_SKIP}};

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

    //#[test]
    #[allow(dead_code)]
    fn bench_send() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/report/rc_send.txt").expect("bla");

        for i in 0..10 {

            println!("Benchmark send RC: starting {:?} of 10", i);

            // Alternating. Alice and Bob take turns sending messages. 
            // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
            let (mut alice_state, mut bob_state) = init_all();
            let associated_data = [0u8;32];
            let plaintext_alice = b"Hello everyone, this is an average sized text.";
            let plaintext_bob = b"This could be an answer to a text.";
            for _ in 0..5000 {
                let start = SystemTime::now();
                let (_, header, ct) = send(&mut alice_state, &associated_data, plaintext_alice);
                #[allow(unused_must_use)] {

                    file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                    file.write_all(b"\n").unwrap();
                }
                let (acc, _, decrypted_plaintext) = receive(&mut bob_state, &associated_data, header, &ct);
                assert_eq!(acc, true);
                assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

                let (_, header, ct) = send(&mut bob_state, &associated_data, plaintext_bob);
                let (acc, _, decrypted_plaintext) = receive(&mut alice_state, &associated_data, header, &ct);
                assert_eq!(acc, true);
                assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
            }
            file.write_all(b"=\n").unwrap();
        }
    }
    //#[test]
    #[allow(dead_code)]
    fn bench_receive() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/report/rc_receive.txt").expect("bla");

        for i in 0..10 {

            println!("Benchmark receive RC: starting {:?} of 10", i);

            // Alternating. Alice and Bob take turns sending messages. 
            // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
            let (mut alice_state, mut bob_state) = init_all();
            let associated_data = [0u8;32];
            let plaintext_alice = b"Hello everyone, this is an average sized text.";
            let plaintext_bob = b"This could be an answer to a text.";
            for _ in 0..5000 {
                let (_, header, ct) = send(&mut alice_state, &associated_data, plaintext_alice);
    
                let start = SystemTime::now();
                let (acc, _, decrypted_plaintext) = receive(&mut bob_state, &associated_data, header, &ct);
                #[allow(unused_must_use)] {
                    file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                    file.write_all(b"\n").unwrap();
                }
                assert_eq!(acc, true);
                assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

                let (_, header, ct) = send(&mut bob_state, &associated_data, plaintext_bob);
                let (acc, _, decrypted_plaintext) = receive(&mut alice_state, &associated_data, header, &ct);
                assert_eq!(acc, true);
                assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
            }
            file.write_all(b"=\n").unwrap();
        }
    }
}










