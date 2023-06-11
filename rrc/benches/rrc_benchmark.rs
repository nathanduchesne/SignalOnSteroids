use criterion::{criterion_group, criterion_main, Criterion, black_box};
use rrc::protocol::{rrc_init_all, Security};

fn init_all_benchmark(c: &mut Criterion) {
    c.bench_function(
        "Initialize states ", 
        |b| b.iter(|| black_box(rrc_init_all(Security::RRidAndSRid)))
    );
}

  



// Lists all benchmark functions from the 'benches' group.
criterion_group!(benches, init_all_benchmark);
// Acts as a main function and runs all benchamrks in 'benches' group
criterion_main!(benches);