#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, time::SystemTime, collections::HashSet};
    use bytevec::{ByteDecodable, ByteEncodable};
    use mset_mu_hash::RistrettoHash;
    use rc::{Ordinal, Header};
    use sha2::Sha512;


    use crate::{protocol::{rrc_init_all, rrc_send, rrc_receive, send_bytes, receive_bytes, Message, Security, Ciphertext, incremental_hash_fct_of_whole_set, incremental_hash_sets_are_equal, update_incremental_hash_set, get_hash_ordinal_set, get_hash_msg_set}, optimized_rrc_send, optimized_rrc_receive, rrc_init_all_optimized_send};

    #[test]
    fn send_receive_bytes_works() {
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let bytes = send_bytes(&mut alice_state, &associated_data, plaintext);
        let (acc, _, decrypted_plaintext) = receive_bytes(&bytes, &mut bob_state, &associated_data);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }

    //#[test]
    #[allow(dead_code)]
    fn memory_benchmark_for_encoded_data_to_send() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/payloadMemory_rrc_alternating.txt").expect("bla");

        // Alternating. Alice and Bob take turns sending messages. 
        // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::SRid);
        let associated_data = [0u8;32];
        let plaintext_alice = b"Hello everyone, this is an average sized text.";
        let plaintext_bob = b"This could be an answer to a text.";
        for i in 1..1500 {
            let bytes = send_bytes(&mut alice_state, &associated_data, plaintext_alice);
            #[allow(unused_must_use)] {

                file.write(i.to_string().as_bytes());
                file.write(b" ");
                file.write(bytes.len().to_string().as_bytes());
                file.write_all(b"\n"); 
            }
            let (acc, _, decrypted_plaintext) = receive_bytes(&bytes, &mut bob_state, &associated_data);
            assert_eq!(acc, true);
            assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

            let bytes = send_bytes(&mut bob_state, &associated_data, plaintext_bob);
            let (acc, _, decrypted_plaintext) = receive_bytes(&bytes, &mut alice_state, &associated_data);
            assert_eq!(acc, true);
            assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
            
        }
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
    fn encoding_hash_set_to_byte_array_works() {
        let mut test_hash_set = HashSet::<Message>::new();
        for i in 0..2000 {
            test_hash_set.insert(Message { ordinal: Ordinal { epoch: i, index: i }, content: [12;32] });
        }

        let test = test_hash_set.encode::<u32>();
        let result_hash_set: HashSet<Message> = HashSet::decode::<u32>(&test.unwrap()).unwrap();
        for i in 0..2000 {
            assert_eq!(result_hash_set.contains(&Message { ordinal: Ordinal { epoch: i, index: i }, content: [12;32] }), true);
        }

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
        let associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext);
        let (acc, _, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let plaintext_2 = b"Let me ping you again";
        let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext_2);
        let (acc, _, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_2.to_vec(), decrypted_plaintext);

        let plaintext_3 = b"My bad I missed your first message! Let me call you back";
        let (_, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, plaintext_3);
        let (acc, _, decrypted_plaintext) = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
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

        let _ = rrc_send(&mut alice_state, &associated_data, plaintext1);
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

        let _ = rrc_send(&mut alice_state, &associated_data, plaintext1);
        let mut corrupted_state = alice_state.clone();
        let _ = rrc_send(&mut alice_state, &associated_data, plaintext2);

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
        let (alice_state, _) = rrc_init_all(Security::RRidAndSRid);
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
        let (alice_state, _) = rrc_init_all(Security::RRidAndSRid);
        let msg1 = Message{ordinal: Ordinal { epoch: 1, index: 1 }, content: [17;32]};
        let msg2 = Message{ordinal: Ordinal { epoch: 1, index: 2 }, content: [19;32]};

        let mut set1 = HashSet::new();
        set1.insert(msg1.clone());
        set1.insert(msg2.clone());
        let hash_set1 = incremental_hash_fct_of_whole_set(&set1, &alice_state.hash_key_prime);

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
        let (alice_state, _) = rrc_init_all(Security::RRidAndSRid);
        let msg1 = Message{ordinal: Ordinal { epoch: 1, index: 1 }, content: [17;32]};
        let msg2 = Message{ordinal: Ordinal { epoch: 1, index: 2 }, content: [19;32]};

        let mut set1 = HashSet::new();
        set1.insert(msg1.clone());
        set1.insert(msg2.clone());
        let hash_set1 = incremental_hash_fct_of_whole_set(&set1, &alice_state.hash_key_prime);

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
        let associated_data = [0u8;32];
        let plaintext = b"Wassup my dude?";
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);

        let plaintext_2 = b"Let me ping you again";
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext_2);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext_2.to_vec(), decrypted_plaintext);

        let plaintext_3 = b"My bad I missed your first message! Let me call you back";
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, plaintext_3);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
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
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, &plaintext);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
        let plaintext = (i*17 as u8).to_be_bytes();
        let (_, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, &plaintext);
        let (acc, _, decrypted_plaintext) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }
    }

    #[test]
    fn incremental_ristretto_hash_works_w_finalize() {
        let mut hash1 = RistrettoHash::<Sha512>::default();
        hash1.add(b"test", 1);
        hash1.add(b"test", 1);

        let mut hash2 = RistrettoHash::<Sha512>::default();
        hash2.add(b"test", 2);

        assert_eq!(hash1.finalize(), hash2.finalize());
    }



    // The goal of this test is to have a similar benchmark to the one in "Optimal Symmetric Ratcheting for Secure Communication" p25/26
    // Since this does not actually test anything, it is not run by default: uncomment the following line to do so.
    #[allow(dead_code)]
    //#[test]
    fn benchmarks_total_exec() {
        let message = b"This will be sent by both participants";
        let associated_data = [0u8;32];

        let mut file = File::create("../../../Report/Plots/BenchLogs/typesOfCommunication.txt").expect("bla");

        let nbr_different_runs = 15;

        // Alternating. Alice and Bob take turns sending messages. 
        // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
        for i in 1..nbr_different_runs + 1 {
            let total_nbr_msgs = 100 * i;
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let start = SystemTime::now();
            for msg_nbr in 0..total_nbr_msgs {
                if msg_nbr % 2 == 0 {
                    let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    let _ = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                }
                else {
                    let (_, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    let _ = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
                }
            }
            #[allow(unused_must_use)] {
                file.write(i.to_string().as_bytes());
                file.write(b" ");
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
            }
        }

        // Unidirectional. Alice first sends n/2 messages to Bob, and after receiving them Bob responds with the remaining n/2 messages.
        for i in 1..nbr_different_runs + 1 {
            let total_nbr_msgs = 100 * i;
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let start = SystemTime::now();
            for msg_nbr in 0..total_nbr_msgs {
                if msg_nbr < total_nbr_msgs / 2 {
                    let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    let _ = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                }
                else {
                    let (_, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    let _ = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
                }
            }
            #[allow(unused_must_use)] {
                file.write(i.to_string().as_bytes());
                file.write(b" ");
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
            }
        }

        // Deferred unidirectional. Alice first sends n/2 messages to Bob but before he receives them, Bob sends n/2 messages to Alice.
        for i in 1..nbr_different_runs + 1 {
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
                    let (_, ciphertext, header) = rrc_send(&mut alice_state, &associated_data, message);
                    counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
                    alice_cts.push(ciphertext);
                    alice_headers.push(header);
                }
                else {
                    let start = SystemTime::now();
                    let (_, ciphertext, header) = rrc_send(&mut bob_state, &associated_data, message);
                    counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
                    bob_cts.push(ciphertext);
                    bob_headers.push(header);
                }
            }

            for (ciphertext, header) in alice_cts.iter().zip(alice_headers.iter()) {
                let mut ct = (*ciphertext).clone();
                let start = SystemTime::now();
                let _ = rrc_receive(&mut alice_state, &associated_data, &mut ct, *header);
                counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
            }

            for (ciphertext, header) in bob_cts.iter().zip(bob_headers.iter()) {
                let mut ct = (*ciphertext).clone();
                let start = SystemTime::now();
                let _ = rrc_receive(&mut bob_state, &associated_data, &mut ct, *header);
                counter += SystemTime::now().duration_since(start).expect("bla").as_micros();
            }

            #[allow(unused_must_use)] {
                file.write(i.to_string().as_bytes());
                file.write(b" ");
                file.write(counter.to_string().as_bytes());
                file.write_all(b"\n"); 
            }
        }
    }

    //#[test]
    #[allow(dead_code)]
    fn bench_rrc_send() {
        let mut file_send = File::create("../../../Report/Plots/BenchLogs/pres/rrc_send.txt").expect("bla");
        let mut file_recv = File::create("../../../Report/Plots/BenchLogs/pres/rrc_recv.txt").expect("bla");

        // Alternating. Alice and Bob take turns sending messages. 
        // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
        let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
        let associated_data = [0u8;32];
        let plaintext_alice = b"Hello everyone, this is an average sized text.";
        let plaintext_bob = b"This could be an answer to a text.";
        for j in 0..5000 {
            if j % 500 == 0 {
                println!("{:?} / 5000", j);
            }
            let start = SystemTime::now();
            let (_, mut ct, header) = rrc_send(&mut alice_state, &associated_data, plaintext_alice);
            #[allow(unused_must_use)] {
                file_send.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_send.write_all(b"\n").unwrap();
            }
            let start = SystemTime::now();
            let (acc, _, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ct, header);
            #[allow(unused_must_use)] {
                file_recv.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_recv.write_all(b"\n").unwrap();
            }
            assert_eq!(acc, true);
            assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

            let (_, mut ct, header) = rrc_send(&mut bob_state, &associated_data, plaintext_bob);
            let (acc, _, decrypted_plaintext) = rrc_receive(&mut alice_state, &associated_data, &mut ct, header);
            assert_eq!(acc, true);
            assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
        }
    }

    //#[test]
    #[allow(dead_code)]
    fn bench_rrc_receive() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/report/rrc_receive.txt").expect("bla");

        for i in 0..3 {

            println!("Benchmark receive RRC: starting {:?} of 4", i);

            // Alternating. Alice and Bob take turns sending messages. 
            // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let associated_data = [0u8;32];
            let plaintext_alice = b"Hello everyone, this is an average sized text.";
            let plaintext_bob = b"This could be an answer to a text.";
            for j in 0..5000 {
                if j % 500 == 0 {
                    println!("{:?} / 5000", j);
                }
                let (_, mut ct, header) = rrc_send(&mut alice_state, &associated_data, plaintext_alice);
                
                let start = SystemTime::now();
                let (acc, _, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ct, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file.write_all(b"\n").unwrap();
                
                assert_eq!(acc, true);
                assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

                let (_, mut ct, header) = rrc_send(&mut bob_state, &associated_data, plaintext_bob);
                let (acc, _, decrypted_plaintext) = rrc_receive(&mut alice_state, &associated_data, &mut ct, header);
                assert_eq!(acc, true);
                assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
            }
            file.write_all(b"=\n").unwrap();
        }
    }

    //#[test]
    #[allow(dead_code)]
    fn benchmark_rcv_r_rid() { 
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/report/rrc_receive_r_rid.txt").expect("bla");
        let plaintext = b"J'ai mis cerbere en enfer.";

        for iter in 0..3 {
            println!("Starting epoch {:?} of rcv with r-RID", iter);
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
            let associated_data = [0;32]; 
            for msg_nbr in 0..5000 {
                if msg_nbr % 500 == 0 {
                    println!("Done {:?} / 3000", msg_nbr);
                }
                let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext);
                let start = SystemTime::now();
                let _ = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file.write_all(b"\n").unwrap(); 
                let (_, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, plaintext);        
                let _ = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            }
            file.write_all(b"=\n").unwrap(); 
        }

    }
    //#[test]
    #[allow(dead_code)]
    fn benchmark_rcv_s_rid() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/report/rrc_receive_s_rid.txt").expect("bla");
        let plaintext = b"J'ai mis cerbere en enfer.";

        for iter in 0..3 {
            println!("Starting epoch {:?} of rcv with s-RID", iter);
            let (mut alice_state, mut bob_state) = rrc_init_all(Security::SRid);
            let associated_data = [0;32]; 
            for msg_nbr in 0..5000 {
                if msg_nbr % 500 == 0 {
                    println!("Done {:?} / 3000", msg_nbr);
                }
                let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext);
                let start = SystemTime::now();
                let _ = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file.write_all(b"\n").unwrap(); 
                let (_, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, plaintext);        
                let _ = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            }
            file.write_all(b"=\n").unwrap(); 
        }
    }

    #[allow(dead_code)]
    /// Benchmark used for evaluating and measuring runtimes for further graphical analysis
    /// Not run by default due to high overhead compared to the unit tests running time.
    //#[test]
    fn benchmark_opti_receive_and_send_times() {
        let (mut alice_state, mut bob_state) = rrc_init_all_optimized_send(Security::SRid);
        let associated_data: [u8; 32] = [0;32];

        let plaintext_alice = b"Hello I am Alice";
        let plaintext_bob = b"Hello I am Bobby";

        let mut file_receive = File::create("../../../Report/Plots/BenchLogs/report/rrc_receive_opti.txt").expect("bla");
        let mut file_send = File::create("../../../Report/Plots/BenchLogs/report/rrc_send_opti.txt").expect("bla");

        for iter in 0..3 {
            println!("In s-rid opti, round {:?} / 3", iter + 1);
            // For multiple rounds
            for _ in 0..5 {
                // Alice sends loads of messages
                for _ in 0..1500 {
                    let send_start = SystemTime::now();
                    let (_, mut ct, header) = optimized_rrc_send(&mut alice_state, &associated_data, plaintext_alice);
                    #[allow(unused_must_use)] {
                        file_send.write(SystemTime::now().duration_since(send_start).expect("bla").as_micros().to_string().as_bytes());
                        file_send.write_all(b"\n");
                        let receive_start = SystemTime::now();
                        let (acc, _, pt) = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ct, header);
                        file_receive.write(SystemTime::now().duration_since(receive_start).expect("bla").as_micros().to_string().as_bytes());
                        //println!("Receive time is {}", SystemTime::now().duration_since(receive_start).expect("bla").as_micros().to_string());
                        file_receive.write_all(b"\n");

                        assert_eq!(acc, true);
                    assert_eq!(pt, plaintext_alice);
                    }
                }
                for _ in 0..1500 {
                    let (_, mut ct2, header2) = optimized_rrc_send(&mut bob_state, &associated_data, plaintext_bob);
                    let (acc, _, pt) = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ct2, header2);
                    assert_eq!(acc, true);
                    assert_eq!(pt, plaintext_bob);
                }
            }
            #[allow(unused_must_use)] {
                file_receive.write_all(b"=\n");
                file_send.write_all(b"=\n");
            }
        }
    
    }

}

