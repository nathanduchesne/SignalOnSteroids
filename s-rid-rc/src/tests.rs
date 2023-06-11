#[cfg(test)]
mod tests {
    use std::{fs::File, time::SystemTime, io::Write, collections::HashSet};
    use rc::Ordinal;
    use rrc::Message;

    use crate::protocol::{s_rid_rc_init, s_rid_rc_receive, s_rid_rc_receive_bytes, s_rid_rc_send, s_rid_rc_send_bytes};

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
        let (_, ct) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);

        let (mut acc, _, mut pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct);
        assert_eq!(acc, true);
        assert_eq!(pt, plaintext_alice);
        let plaintext_bob = b"Hello Alice, pleasure to meet you, I am Bobathan";
        let (_, ct2) = s_rid_rc_send(&mut bob_state, &associated_data, plaintext_bob);

        (acc, _, pt) = s_rid_rc_receive(&mut alice_state, &associated_data, ct2);
        assert_eq!(acc, true);
        assert_eq!(pt, plaintext_bob);

    }

    #[test]
    fn two_round_trip_epochs_works() {
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data: [u8; 32] = [0;32];

        for _ in 0..10 {
            // Alice sends
            let plaintext_alice = b"Hello I am Alice";
            let (_, ct) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);
            // Bob receives
            let (acc, _, pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct);
            assert_eq!(acc, true);
            assert_eq!(pt, plaintext_alice);
            // Bob sends
            let plaintext_bob = b"Hello Alice, pleasure to meet you, I am Bobathan";
            let (_, ct2) = s_rid_rc_send(&mut bob_state, &associated_data, plaintext_bob);
            // Alice receives
            let (acc, _, pt) = s_rid_rc_receive(&mut alice_state, &associated_data, ct2);
            assert_eq!(acc, true);
            assert_eq!(pt, plaintext_bob);
        }
    }


    #[test]
    fn adversary_with_forged_msg_is_detected() {
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data: [u8; 32] = [0;32];
        // Alice's state is compromised by Eve
        let mut eve_state = alice_state.clone();
        let plaintext_eve = b"Hello I am Alxce";
        let (_, ct_eve) = s_rid_rc_send(&mut eve_state, &associated_data, plaintext_eve);

        let plaintext_alice = b"Hello I am Alice";
        let (_, _) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);

        let (mut acc, _, mut pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct_eve);
        assert_eq!(acc, true);
        assert_eq!(pt, plaintext_eve);

        let plaintext_bob = b"Hello Alxce, pleasure to meet you, I am Bobathan";
        let (_, ct2) = s_rid_rc_send(&mut bob_state, &associated_data, plaintext_bob);

        // Alice detects that a forgery was created in her name
        (acc, _, pt) = s_rid_rc_receive(&mut alice_state, &associated_data, ct2);
        assert_eq!(acc, false);
        assert_eq!(pt, Vec::new());
    }

    #[test]
    fn send_and_receive_bytes_works() {
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data = [34u8; 32];
        let plaintext = b"This is the plaintext used to test out the implementation.";
        let bytes = s_rid_rc_send_bytes(&mut alice_state, &associated_data, plaintext);
        let (acc, _, received_plaintext) = s_rid_rc_receive_bytes(&mut bob_state, &associated_data, &bytes);
        assert_eq!(acc, true);
        assert_eq!(plaintext.to_vec(), received_plaintext);
    }

    #[allow(dead_code)]
    //#[test]
    fn send_and_receive_bytes_alternate_for_benchmark() {
        let mut file = File::create("../../../Report/Plots/BenchLogs/payloadMemory_s_rid_rc_alternating.txt").expect("bla");

        // Alternating. Alice and Bob take turns sending messages. 
        // Alice sends the even-numbered messages and Bob sends the odd-numbered messages.
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data = [0u8;32];
        let plaintext_alice = b"Hello everyone, this is an average sized text.";
        let plaintext_bob = b"This could be an answer to a text.";
        for i in 1..1500 {
            let bytes = s_rid_rc_send_bytes(&mut alice_state, &associated_data, plaintext_alice);
            #[allow(unused_must_use)] {
                file.write(i.to_string().as_bytes());
                file.write(b" ");
                file.write(bytes.len().to_string().as_bytes());
                file.write_all(b"\n"); 
            }
            let (acc, _, decrypted_plaintext) = s_rid_rc_receive_bytes(&mut bob_state, &associated_data, &bytes);
            assert_eq!(acc, true);
            assert_eq!(plaintext_alice.to_vec(), decrypted_plaintext);

            let bytes = s_rid_rc_send_bytes(&mut bob_state, &associated_data, plaintext_bob);
            let (acc, _, decrypted_plaintext) = s_rid_rc_receive_bytes(&mut alice_state, &associated_data, &bytes);
            assert_eq!(acc, true);
            assert_eq!(plaintext_bob.to_vec(), decrypted_plaintext);
            
        }
    }

    #[allow(dead_code)]
    /// Benchmark used for evaluating and measuring runtimes for further graphical analysis
    /// Not run by default due to high overhead compared to the unit tests running time.
    //#[test]
    fn benchmark_receive_and_send_times() {
        let (mut alice_state, mut bob_state) = s_rid_rc_init();
        let associated_data: [u8; 32] = [0;32];

        let plaintext_alice = b"Hello I am Alice";
        let plaintext_bob = b"Hello I am Bobby";

        let mut file_receive = File::create("../../../Report/Plots/BenchLogs/report/s_rid_rc_receive_opti.txt").expect("bla");
        let mut file_send = File::create("../../../Report/Plots/BenchLogs/report/s_rid_rc_send_opti.txt").expect("bla");

            // For multiple rounds
            for _ in 0..10 {
                // Alice sends loads of messages
                for _ in 0..100 {
                    let send_start = SystemTime::now();
                    let (_, ct) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);
                    #[allow(unused_must_use)] {
                        file_send.write(SystemTime::now().duration_since(send_start).expect("bla").as_micros().to_string().as_bytes());
                        file_send.write_all(b"\n");
                        let receive_start = SystemTime::now();
                        let (acc, _, pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct);
                        file_receive.write(SystemTime::now().duration_since(receive_start).expect("bla").as_micros().to_string().as_bytes());
                        file_receive.write_all(b"\n");

                        assert_eq!(acc, true);
                    assert_eq!(pt, plaintext_alice);
                    }
                }
                for _ in 0..100 {
                    let (_, ct2) = s_rid_rc_send(&mut bob_state, &associated_data, plaintext_bob);
                    let (acc, _, pt) = s_rid_rc_receive(&mut alice_state, &associated_data, ct2);
                    assert_eq!(acc, true);
                    assert_eq!(pt, plaintext_bob);
                }
            }
    }
}
