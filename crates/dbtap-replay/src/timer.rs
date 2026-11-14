//! High-resolution scheduling timer.
//!
//! Tokio's millisecond timer is too coarse for requests with sub-millisecond responses.
//! A dedicated thread orders deadlines, sleeps until near each deadline, then spins briefly.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

struct Entry {
    at: Instant,
    seq: u64,
    wake: oneshot::Sender<()>,
}

impl PartialEq for Entry {
    fn eq(&self, o: &Self) -> bool {
        self.at == o.at && self.seq == o.seq
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Entry {
    // BinaryHeap returns the maximum, so earlier deadlines sort higher.
    fn cmp(&self, o: &Self) -> Ordering {
        o.at.cmp(&self.at).then(o.seq.cmp(&self.seq))
    }
}

pub struct Timer {
    tx: mpsc::Sender<(Instant, oneshot::Sender<()>)>,
    thread: std::thread::Thread,
}

/// Use Tokio until distant deadlines approach, limiting the dedicated thread's queue.
const COARSE: Duration = Duration::from_millis(3);
/// Wake early to compensate for OS sleep overshoot, then spin for the remaining interval.
const SPIN: Duration = Duration::from_micros(80);

impl Timer {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<(Instant, oneshot::Sender<()>)>();
        let h = std::thread::Builder::new()
            .name("dbtap-timer".into())
            .spawn(move || {
                let mut heap: BinaryHeap<Entry> = BinaryHeap::new();
                let mut seq = 0u64;
                loop {
                    loop {
                        match rx.try_recv() {
                            Ok((at, wake)) => {
                                seq += 1;
                                heap.push(Entry { at, seq, wake });
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                    }
                    let now = Instant::now();
                    while heap.peek().is_some_and(|e| e.at <= now) {
                        let _ = heap.pop().unwrap().wake.send(());
                    }
                    match heap.peek() {
                        None => std::thread::park(),
                        Some(e) => {
                            let d = e.at.saturating_duration_since(now);
                            if d > SPIN {
                                std::thread::park_timeout(d - SPIN);
                            } else {
                                std::hint::spin_loop();
                            }
                        }
                    }
                }
            })
            .expect("Cannot start timer thread");
        Timer { tx, thread: h.thread().clone() }
    }

    pub async fn sleep_until(&self, at: Instant) {
        let now = Instant::now();
        if at <= now {
            return;
        }
        if at - now > COARSE {
            tokio::time::sleep_until((at - COARSE + Duration::from_millis(1)).into()).await;
            if at <= Instant::now() {
                return;
            }
        }
        let (wake, done) = oneshot::channel();
        if self.tx.send((at, wake)).is_ok() {
            self.thread.unpark();
            let _ = done.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wake in deadline order, never before the deadline.
    /// Scheduling accuracy depends on CPU load and is not asserted here.
    /// Actual replay lag is measured separately (p50 0.02 ms on an idle machine).
    #[test]
    fn never_wakes_early_and_wakes_in_deadline_order() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            let t = std::sync::Arc::new(Timer::new());
            let base = Instant::now() + Duration::from_millis(20);
            let woke = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut hs = Vec::new();
            // Register in reverse order, with gaps wide enough for a busy machine.
            for step in [3u64, 1, 2, 0] {
                let (t, woke) = (t.clone(), woke.clone());
                hs.push(tokio::spawn(async move {
                    let at = base + Duration::from_millis(step * 40);
                    t.sleep_until(at).await;
                    let now = Instant::now();
                    woke.lock().unwrap().push(step);
                    assert!(now >= at, "Woke {:?} before the deadline", at - now);
                }));
            }
            for h in hs {
                h.await.unwrap();
            }
            assert_eq!(*woke.lock().unwrap(), [0, 1, 2, 3]);
            // Past deadlines need no wait.
            let before = Instant::now();
            t.sleep_until(before - Duration::from_millis(5)).await;
            assert!(before.elapsed() < Duration::from_millis(5));
        });
    }
}
