//! Criterion benchmark — TGS-REQ throughput (requests per second).
//!
//! Sets up an in-process `TestHarness` with one user principal + one
//! service principal, then repeatedly calls
//! `TestHarness::tgs_req("alice", "host/web.example.com")` and measures
//! the end-to-end TGS-REQ → TGS-REP throughput (each iteration performs
//! an AS-REQ first to obtain the TGT, then the TGS-REQ).

use adrian_test_harness::TestHarness;
use criterion::{criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

fn bench_tgs_req(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let harness = rt.block_on(async {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        h.create_service_principal("web.example.com", "svc-password")
            .await
            .expect("create svc");
        h
    });

    c.bench_function("tgs_req", |b| {
        b.iter(|| {
            rt.block_on(async {
                harness
                    .tgs_req("alice", "host/web.example.com")
                    .await
                    .expect("TGS-REQ");
            })
        });
    });
}

criterion_group!(benches, bench_tgs_req);
criterion_main!(benches);
