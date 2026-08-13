//! Criterion benchmark — AS-REQ throughput (requests per second).
//!
//! Sets up an in-process `TestHarness` with one user principal, then
//! repeatedly calls `TestHarness::as_req("alice")` and measures the
//! end-to-end AS-REQ → AS-REP throughput.
//!
//! Run with: `cargo bench -p adrian-test-harness --bench as_req`.

use adrian_test_harness::TestHarness;
use criterion::{criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

fn bench_as_req(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let harness = rt.block_on(async {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        h
    });

    c.bench_function("as_req", |b| {
        b.iter(|| {
            rt.block_on(async {
                harness.as_req("alice").await.expect("AS-REQ");
            })
        });
    });
}

criterion_group!(benches, bench_as_req);
criterion_main!(benches);
