#[cfg(test)]
mod tests {
    use std::{time::SystemTime, fs::File, io::Write};

    use rand::Rng;

    use crate::{arc_init, arc_send, arc_receive, arc_auth_send, arc_auth_receive};


    #[test]
    fn protocol_has_liveness() {
        let associated_data: [u8; 32] = [22; 32];
        let (mut alice_state, mut bob_state) = arc_init();

        for _ in 0..15 {
            // Randomly pick a message content for Alice and send it
            let mut alice_pt = [0u8; 85];
            rand::thread_rng().fill(&mut alice_pt[..]);
            let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &alice_pt);
            let (acc, _, pt) = arc_receive(&mut bob_state, &associated_data, header, ct);
            assert_eq!(acc, true);
            assert_eq!(pt, alice_pt);

            // Randomly pick an answer for Bob and send it
            let mut bob_pt = [0u8; 123];
            rand::thread_rng().fill(&mut bob_pt[..]);
            let (_, header, ct) = arc_send(&mut bob_state, &associated_data, &bob_pt);
            let (acc, _, pt) = arc_receive(&mut alice_state, &associated_data, header, ct);
            assert_eq!(acc, true);
            assert_eq!(pt, bob_pt);
        }

        // Alice send an authentication tag to check for forgeries
        let (_, at) = arc_auth_send(&mut alice_state);
        let (acc, _) = arc_auth_receive(&mut bob_state, at);
        assert_eq!(acc, true);
        // Bob sends an authentication tag to check for forgeries
        let (_, at) = arc_auth_send(&mut bob_state);
        let (acc, _) = arc_auth_receive(&mut alice_state, at);
        assert_eq!(acc, true);
    }

    #[test]
    fn protocol_has_safety() {
        let associated_data: [u8; 32] = [22; 32];
        let (mut alice_state, mut bob_state) = arc_init();

        for _ in 0..15 {
            // Randomly pick a message content for Alice and send it
            let mut alice_pt = [0u8; 85];
            rand::thread_rng().fill(&mut alice_pt[..]);
            let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &alice_pt);
            let (acc, _, pt) = arc_receive(&mut bob_state, &associated_data, header, ct);
            assert_eq!(acc, true);
            assert_eq!(pt, alice_pt);

            // Randomly pick an answer for Bob and send it
            let mut bob_pt = [0u8; 123];
            rand::thread_rng().fill(&mut bob_pt[..]);
            let (_, header, ct) = arc_send(&mut bob_state, &associated_data, &bob_pt);
            let (acc, _, pt) = arc_receive(&mut alice_state, &associated_data, header, ct);
            assert_eq!(acc, true);
            assert_eq!(pt, bob_pt);
        }
        let mut eve_state = alice_state.clone();
        // Send a forgery to Bob
        let (_, header, ct) = arc_send(&mut eve_state, &associated_data, b"I am surely not an adversary");
        let (_, _, _) = arc_receive(&mut bob_state, &associated_data, header, ct);

        // Alice send an authentication tag to check for forgeries
        let (_, at) = arc_auth_send(&mut alice_state);
        let (acc, _) = arc_auth_receive(&mut bob_state, at); 
        assert_eq!(acc, true);
        // Bob sends an authentication tag to check for forgeries
        let (_, at) = arc_auth_send(&mut bob_state);
        let (acc, _) = arc_auth_receive(&mut alice_state, at); // -> fails since Eve sent a forgery on Alice's behalf
        assert_eq!(acc, false);
    }

    #[allow(dead_code)]
    //#[test]
    fn receive_send_bench() {
        let mut file_runtime_send = File::create("../../../Report/Plots/BenchLogs/report/unf_arc_rc_send.txt").expect("bla");
        let mut file_runtime_recv = File::create("../../../Report/Plots/BenchLogs/report/unf_arc_rc_recv.txt").expect("bla");
        let plaintext = *b"J'ai mis cerbere en enfer.";
        let (mut alice_state, mut bob_state) = arc_init();
    
        let associated_data = [0u8;32];
    
        for _ in 0..2000 {
                let start = SystemTime::now();
                let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &plaintext);
                file_runtime_send.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_runtime_send.write_all(b"\n").unwrap();
    
                let start = SystemTime::now();
                let (_, _, _) = arc_receive(&mut bob_state, &associated_data, header, ct);
                file_runtime_recv.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_runtime_recv.write_all(b"\n").unwrap();
                let (_, header, ct) = arc_send(&mut bob_state, &associated_data, &plaintext);
                let (acc, _, _) = arc_receive(&mut alice_state, &associated_data, header, ct);
                assert_eq!(acc, true);
        }
        let start = SystemTime::now();
        let (_, at) = arc_auth_send(&mut alice_state);
        println!("RC Auth send after 10k messages takes {:?} microseconds", SystemTime::now().duration_since(start).unwrap().as_micros());
        let start = SystemTime::now();
        let (acc, _,) = arc_auth_receive(&mut bob_state, at);
        println!("RC Auth receive after 10k messages takes {:?} microseconds", SystemTime::now().duration_since(start).unwrap().as_micros());
        assert_eq!(acc, true);

    }
}