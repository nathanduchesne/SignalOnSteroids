use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, black_box};
use rrc::{rrc_init_all, RRC_State, rrc_send, rrc_receive};
use std::fs::{File};
use std::io::prelude::*;

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| rrc_init_all(rrc::Security::r_RID_and_s_RID))
    );
}

fn ratchet_encrypt_benchmark(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: RRC_State;
    alice_state = black_box(rrc_init_all(rrc::Security::r_RID_and_s_RID).0);

    let mut associated_data = black_box(
        [0;32]
    );
    let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_send_alice_spams_bob.txt").expect("bla");
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| {
            let start = SystemTime::now();
            rrc_send(&mut alice_state, &mut associated_data, &plaintext);
            file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
            file.write_all(b"\n");
        })
    );
}

    fn ratchet_decrypt_benchmark(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RRC_State;
        let mut bob_state: RRC_State;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::r_RID_and_s_RID));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_receive_alice_spams_bob.txt").expect("bla");

        c.bench_function(
            "Ratchet receive ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n");            
            })
        );
    }


// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, ratchet_encrypt_benchmark, ratchet_decrypt_benchmark);
// Acts as a main function and runs all benchamrks in 'benches' group
criterion_main!(benches);