use criterion::{criterion_group, criterion_main, Criterion, black_box};
use unf_arc_based_on_rrc::{rc_arc_init, rc_arc_send, rc_arc_receive, rc_arc_auth_receive, rc_arc_auth_send};

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| rc_arc_init())
    );
}

fn auth_send(c: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let (mut alice_state, mut bob_state) = black_box(rc_arc_init());

    let associated_data = black_box(
        [0u8;32]
    );
    for _ in 0..2000 {
        let mut wrapper = rc_arc_send(&mut alice_state, &associated_data, &plaintext);
        let (_, _, _) = rc_arc_receive(&mut bob_state, &associated_data, &mut wrapper);
        let mut wrapper = rc_arc_send(&mut bob_state, &associated_data, &plaintext);
        let (_, _, _) = rc_arc_receive(&mut alice_state, &associated_data, &mut wrapper);
    }
    c.bench_function(
        "Ratchet send ", 
        |b| b.iter(|| {
            let _ = rc_arc_auth_send(&mut alice_state);
        })
    );
}

fn auth_recv(_: &mut Criterion) {
    let plaintext = black_box(
        *b"J'ai mis cerbere en enfer."
    );
    let (mut alice_state, mut bob_state) = black_box(rc_arc_init());

    let associated_data = black_box(
        [0u8;32]
    );
    for _ in 0..2000 {
        let mut wrapper = rc_arc_send(&mut alice_state, &associated_data, &plaintext);
        let (_, _, _) = rc_arc_receive(&mut bob_state, &associated_data, &mut wrapper);
        let mut wrapper = rc_arc_send(&mut bob_state, &associated_data, &plaintext);
        let (_, _, _) = rc_arc_receive(&mut alice_state, &associated_data, &mut wrapper);
    }

    let mut wrapper = rc_arc_auth_send(&mut alice_state);
    let (acc, _) = rc_arc_auth_receive(&mut bob_state, &mut wrapper);
    assert_eq!(acc, true);
}



// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark, auth_send, auth_recv);
// Acts as a main function and runs all benchmarks in 'benches' group
criterion_main!(benches);