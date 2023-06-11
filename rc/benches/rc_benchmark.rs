use criterion::{criterion_group, criterion_main, Criterion, black_box};
use rc::{init_all, State, receive, send};

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
        |b| b.iter(|| send(&mut alice_state, &associated_data, &plaintext))
    );
}

fn ratchet_decrypt_benchmark(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let mut alice_state: State;
    let mut bob_state: State;
    (alice_state, bob_state) = black_box(init_all());
    let associated_data = black_box(  [0;32]);


    c.bench_function(
        "Ratchet send & receive ", 
        |b| b.iter(|| 
            {
                let (_, header, ciphertext) = send(&mut alice_state, &associated_data, &plaintext);
                receive(&mut bob_state, &associated_data, header, &ciphertext);}
        )
    );
}


// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, ratchet_encrypt_benchmark, ratchet_decrypt_benchmark);
//criterion_group!(benches, send_receive_measures);
// Acts as a main function and runs all benchamrks in 'benches' group
criterion_main!(benches);