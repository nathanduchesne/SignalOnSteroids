#[cfg(test)]
mod tests {
    use std::{fs::File, time::SystemTime, io::Write};
    use rand::Rng;
    use crate::protocol::{rc_arc_init, rc_arc_receive, rc_arc_send, rc_arc_auth_receive, rc_arc_auth_send};

    
    #[test]
    fn protocol_has_liveness() {
        let associated_data: [u8; 32] = [241; 32];
        let (mut alice_state, mut bob_state) = rc_arc_init();

        for _ in 0..15 {
            // Randomly pick a message content for Alice and send it
            let mut alice_pt = [0u8; 85];
            rand::thread_rng().fill(&mut alice_pt[..]);
            let mut ct = rc_arc_send(&mut alice_state, &associated_data, &alice_pt);
            let (acc, _, pt) = rc_arc_receive(&mut bob_state, &associated_data, &mut ct);
            assert_eq!(acc, true);
            assert_eq!(pt, alice_pt);

            // Randomly pick an answer for Bob and send it
            let mut bob_pt = [0u8; 123];
            rand::thread_rng().fill(&mut bob_pt[..]);
            let mut ct = rc_arc_send(&mut bob_state, &associated_data, &bob_pt);
            let (acc, _, pt) = rc_arc_receive(&mut alice_state, &associated_data, &mut ct);
            assert_eq!(acc, true);
            assert_eq!(pt, bob_pt);
        }

        // Alice send an authentication tag to check for forgeries
        let mut at = rc_arc_auth_send(&mut alice_state);
        let (acc, _) = rc_arc_auth_receive(&mut bob_state, &mut at);
        assert_eq!(acc, true);
        // Bob sends an authentication tag to check for forgeries
        let mut at = rc_arc_auth_send(&mut bob_state);
        let (acc, _) = rc_arc_auth_receive(&mut alice_state, &mut at);
        assert_eq!(acc, true);
    }

    #[test]
    fn protocol_has_safety() {
        let associated_data: [u8; 32] = [241; 32];
        let (mut alice_state, mut bob_state) = rc_arc_init();

        for _ in 0..15 {
            // Randomly pick a message content for Alice and send it
            let mut alice_pt = [0u8; 85];
            rand::thread_rng().fill(&mut alice_pt[..]);
            let mut ct = rc_arc_send(&mut alice_state, &associated_data, &alice_pt);
            let (acc, _, pt) = rc_arc_receive(&mut bob_state, &associated_data, &mut ct);
            assert_eq!(acc, true);
            assert_eq!(pt, alice_pt);

            // Randomly pick an answer for Bob and send it
            let mut bob_pt = [0u8; 123];
            rand::thread_rng().fill(&mut bob_pt[..]);
            let mut ct = rc_arc_send(&mut bob_state, &associated_data, &bob_pt);
            let (acc, _, pt) = rc_arc_receive(&mut alice_state, &associated_data, &mut ct);
            assert_eq!(acc, true);
            assert_eq!(pt, bob_pt);
        }

        // Eve compromises Alice's state after the previous communication
        let mut eve_state = alice_state.clone();
        let mut eve_ct = rc_arc_send(&mut eve_state, &associated_data, b"i am not eve!");
        let (acc, _, pt) = rc_arc_receive(&mut bob_state, &associated_data, &mut eve_ct);
        assert_eq!(acc, true);
        assert_eq!(pt, b"i am not eve!");

        // Alice send an authentication tag to check for forgeries
        let mut at = rc_arc_auth_send(&mut alice_state);
        let (acc, _) = rc_arc_auth_receive(&mut bob_state, &mut at);
        assert_eq!(acc, false); // ---> Bob detects that he has received a forgery
        
        // Bob sends an authentication tag to check for forgeries
        let mut at = rc_arc_auth_send(&mut bob_state);
        let (acc, _) = rc_arc_auth_receive(&mut alice_state, &mut at);
        assert_eq!(acc, true); // ---> Alice received nothing abnormal from Bob
    }

    #[allow(dead_code)]
    //#[test]
    fn receive_send_bench() {
        let mut file_runtime_send = File::create("../../../Report/Plots/BenchLogs/report/unf_arc_rrc_send.txt").expect("bla");
        let mut file_runtime_recv = File::create("../../../Report/Plots/BenchLogs/report/unf_arc_rrc_recv.txt").expect("bla");
        let plaintext = *b"J'ai mis cerbere en enfer.";
        let (mut alice_state, mut bob_state) = rc_arc_init();
    
        let associated_data = [0u8;32];
    
        for _ in 0..2000 {
                let start = SystemTime::now();
                let mut wrapper = rc_arc_send(&mut alice_state, &associated_data, &plaintext);
                file_runtime_send.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_runtime_send.write_all(b"\n").unwrap();
    
                let start = SystemTime::now();
                let (_, _, _) = rc_arc_receive(&mut bob_state, &associated_data, &mut wrapper);
                file_runtime_recv.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes()).unwrap();
                file_runtime_recv.write_all(b"\n").unwrap();
                let mut wrapper = rc_arc_send(&mut bob_state, &associated_data, &plaintext);
                let (acc, _, _) = rc_arc_receive(&mut alice_state, &associated_data, &mut wrapper);
                assert_eq!(acc, true);
        }
        let start = SystemTime::now();
        let mut at = rc_arc_auth_send(&mut alice_state);
        println!("RRC Auth send after 10k messages takes {:?} microseconds", SystemTime::now().duration_since(start).unwrap().as_micros());
        let start = SystemTime::now();
        let (acc, _,) = rc_arc_auth_receive(&mut bob_state, &mut at);
        println!("RRC Auth receive after 10k messages takes {:?} microseconds", SystemTime::now().duration_since(start).unwrap().as_micros());
        assert_eq!(acc, true);
    }
}
