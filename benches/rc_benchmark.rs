use criterion::{criterion_group, criterion_main, Criterion, black_box};
use rc::{init_all, State, ratchet_encrypt, ratchet_decrypt};

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| init_all())
    );
}

fn ratchet_encrypt_benchmark(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: State;
    alice_state = black_box(init_all().0);

    let associated_data = black_box(
        [0;5]
    );
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| ratchet_encrypt(&mut alice_state, &plaintext, &associated_data))
    );
}

    fn ratchet_decrypt_benchmark(c: &mut Criterion) {
        let plaintext = black_box(
            *b"J'ai mis cerbere en enfer."
        );
        let mut alice_state: State;
        let mut bob_state: State;
        (alice_state, bob_state) = black_box(init_all());
        let associated_data = black_box(  [0;5]);

        let ciphertext = black_box(ratchet_encrypt(&mut alice_state, &plaintext, &associated_data));
    

        c.bench_function(
            "Ratchet receive ", 
            |b| b.iter(|| ratchet_decrypt(&mut bob_state, ciphertext.0, &ciphertext.1, &associated_data))
        );
    }


// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, ratchet_encrypt_benchmark, ratchet_decrypt_benchmark);
// Acts as a main function and runs all benchamrks in 'benches' group
criterion_main!(benches);