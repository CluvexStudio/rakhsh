use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tracing::info;

pub static TX: AtomicU64 = AtomicU64::new(0);
pub static RX: AtomicU64 = AtomicU64::new(0);

pub fn add_tx(n: usize) {
    TX.fetch_add(n as u64, Relaxed);
}

pub fn add_rx(n: usize) {
    RX.fetch_add(n as u64, Relaxed);
}

pub fn spawn_logger() {
    tokio::spawn(async move {
        let (mut lt, mut lr) = (0u64, 0u64);
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let (t, r) = (TX.load(Relaxed), RX.load(Relaxed));
            let dt = (t.wrapping_sub(lt)) as f64 * 8.0 / 10.0 / 1e6;
            let dr = (r.wrapping_sub(lr)) as f64 * 8.0 / 10.0 / 1e6;
            lt = t;
            lr = r;
            if dt > 0.05 || dr > 0.05 {
                info!("throughput tx={dt:.1} Mbit/s rx={dr:.1} Mbit/s");
            }
        }
    });
}
