use criterion::{criterion_group, criterion_main, Criterion, black_box};
use unf_arc_based_on_rc::{arc_init, arc_send, arc_receive, arc_auth_send, arc_auth_receive};

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| arc_init())
    );
}

fn auth_send(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let (mut alice_state, mut bob_state) = black_box(arc_init());

    let associated_data = black_box(
        [0u8;32]
    );
    for _ in 0..2000 {
        let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &plaintext);
        let (_, _, _) = arc_receive(&mut bob_state, &associated_data, header, ct);
        let (_, header, ct) = arc_send(&mut bob_state, &associated_data, &plaintext);
        let (_, _, _) = arc_receive(&mut alice_state, &associated_data, header, ct);
    }
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| {
            let (num, at) = arc_auth_send(&mut alice_state);
            assert_eq!(num, at.num);
        })
    );
}

fn auth_recv(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let (mut alice_state, mut bob_state) = black_box(arc_init());

    let associated_data = black_box(
        [0u8;32]
    );
    for _ in 0..2000 {
        let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &plaintext);
        let (_, _, _) = arc_receive(&mut bob_state, &associated_data, header, ct);
        let (_, header, ct) = arc_send(&mut bob_state, &associated_data, &plaintext);
        let (_, _, _) = arc_receive(&mut alice_state, &associated_data, header, ct);
    }
    let (_, at) = black_box(arc_auth_send(&mut alice_state));
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| {
            let (acc, _) = arc_auth_receive(&mut bob_state, at.clone());
            assert_eq!(acc, true);
        })
    );
}

// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, auth_send, auth_recv);
// Acts as a main function and runs all benchmarks in 'benches' group
criterion_main!(benches);