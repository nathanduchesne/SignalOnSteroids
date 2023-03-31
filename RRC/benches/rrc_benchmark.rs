use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, Criterion, black_box};
use rrc::{rrc_init_all, RrcState, rrc_send, rrc_receive, rrc_init_all_optimized_send, optimized_rrc_send, optimized_rrc_receive};
use std::fs::{File};
use std::io::prelude::*;

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| rrc_init_all(rrc::Security::RRidAndSRid))
    );
}

fn ratchet_encrypt_benchmark(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: RrcState;
    alice_state = black_box(rrc_init_all(rrc::Security::RRidAndSRid).0);

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

fn optimized_send_benchmark(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: rrc::OptimizedSendRrcState;
    alice_state = black_box(rrc_init_all_optimized_send(rrc::Security::RRidAndSRid).0);

    let mut associated_data = black_box(
        [0;32]
    );
    let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_optimized_send_alice_spams_bob.txt").expect("bla");
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| {
            let start = SystemTime::now();
            optimized_rrc_send(&mut alice_state, &mut associated_data, &plaintext);
            file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
            file.write_all(b"\n");
        })
    );
}

fn optimized_send_back_and_forth(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: rrc::OptimizedSendRrcState;
    let mut bob_state: rrc::OptimizedSendRrcState;
    (alice_state, bob_state) = black_box(rrc_init_all_optimized_send(rrc::Security::RRidAndSRid));
    let mut associated_data = black_box(  [0;32]);  

    let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_optimized_send_alice_and_bob_back_and_forth.txt").expect("bla");

    c.bench_function(
        "Ratchet send back&forth ", 
        |b| b.iter(|| {
            let start = SystemTime::now();
            let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, &plaintext);
            file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
            file.write_all(b"\n"); 
            let result = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
            let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, &plaintext);        
            let result = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
        })
    );
}


    fn ratchet_decrypt_benchmark(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RrcState;
        let mut bob_state: RrcState;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::RRidAndSRid));
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

    fn optimized_receive_benchmark(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: rrc::OptimizedSendRrcState;
        let mut bob_state: rrc::OptimizedSendRrcState;
        (alice_state, bob_state) = black_box(rrc_init_all_optimized_send(rrc::Security::RRidAndSRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_optimized_receive_alice_spams_bob.txt").expect("bla");

        c.bench_function(
            "Ratchet receive ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n");            
            })
        );
    }

    fn optimized_receive_benchmark_back_and_forth(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: rrc::OptimizedSendRrcState;
        let mut bob_state: rrc::OptimizedSendRrcState;
        (alice_state, bob_state) = black_box(rrc_init_all_optimized_send(rrc::Security::RRidAndSRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_optimized_receive_back_and_forthtxt").expect("bla");

        c.bench_function(
            "Ratchet receive ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = optimized_rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n");       
                let (ordinal, mut ciphertext, header) = optimized_rrc_send(&mut bob_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = optimized_rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);     
            })
        );
    }

    fn ratchet_encrypt_decrypt_benchmark(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RrcState;
        let mut bob_state: RrcState;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::RRidAndSRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_receive_alice_and_bob_back_and_forth.txt").expect("bla");

        c.bench_function(
            "Ratchet receive back&forth ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
                let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, &plaintext);        
                let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            })
        );
    }

    fn ratchet_encrypt_decrypt_benchmark2(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RrcState;
        let mut bob_state: RrcState;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::RRidAndSRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_send_alice_and_bob_back_and_forth.txt").expect("bla");

        c.bench_function(
            "Ratchet send back&forth ", 
            |b| b.iter(|| {
                let start = SystemTime::now();
                let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, &plaintext);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, &plaintext);        
                let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            })
        );
    }

    fn ratchet_encrypt_decrypt_benchmarks_s_rid(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RrcState;
        let mut bob_state: RrcState;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::SRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_receive_alice_and_bob_back_and_forth_s_rid.txt").expect("bla");

        c.bench_function(
            "Ratchet receive s_rid back&forth ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
                let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, &plaintext);        
                let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            })
        );
    }

    fn ratchet_encrypt_decrypt_benchmarks_r_rid(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: RrcState;
        let mut bob_state: RrcState;
        (alice_state, bob_state) = black_box(rrc_init_all(rrc::Security::RRid));
        let mut associated_data = black_box(  [0;32]);  
 
        let mut file = File::create("../../../Report/Plots/BenchLogs/rrc_receive_alice_and_bob_back_and_forth_r_rid.txt").expect("bla");

        c.bench_function(
            "Ratchet receive r_rid back&forth ", 
            |b| b.iter(|| {
                let (ordinal, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, &plaintext);
                let start = SystemTime::now();
                let result = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
                file.write(SystemTime::now().duration_since(start).expect("bla").as_micros().to_string().as_bytes());
                file.write_all(b"\n"); 
                let (ordinal, mut ciphertext, header) = rrc_send(&mut bob_state, &associated_data, &plaintext);        
                let result = rrc_receive(&mut alice_state, &associated_data, &mut ciphertext, header);
            })
        );
    }



// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, ratchet_encrypt_benchmark, ratchet_decrypt_benchmark, ratchet_encrypt_decrypt_benchmark, ratchet_encrypt_decrypt_benchmark2, ratchet_encrypt_decrypt_benchmarks_s_rid, ratchet_encrypt_decrypt_benchmarks_r_rid, optimized_send_benchmark, optimized_receive_benchmark, optimized_send_back_and_forth, optimized_receive_benchmark_back_and_forth);
// Acts as a main function and runs all benchamrks in 'benches' group
criterion_main!(benches);