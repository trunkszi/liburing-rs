use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use liburing::{CrossThreadCommandQueue, UringError};

use super::*;

#[test]
fn bounded_cross_thread_waker_batch_drain_recovers_backpressure_without_loss() -> TestResult {
    let _serial = crate::kernel_test_lock();
    const PRODUCERS: usize = 4;
    const PER_PRODUCER: usize = 1_024;
    let mut proactor = kernel(true)?;
    let queue = CrossThreadCommandQueue::new(8, proactor.waker().expect("enabled waker"));
    let blocked = Arc::new(AtomicUsize::new(0));
    // Force queue saturation before starting consumers, independently of scheduling.
    for sequence in 0..queue.capacity() {
        queue.push((PRODUCERS, sequence))?;
    }
    assert_eq!(
        queue.push((PRODUCERS, 8)),
        Err(UringError::CommandQueueFull)
    );
    let gate = Arc::new(Barrier::new(PRODUCERS + 1));
    let start = Instant::now();
    thread::scope(|scope| -> TestResult {
        let mut workers = Vec::new();
        for producer in 0..PRODUCERS {
            let queue = queue.clone();
            let gate = Arc::clone(&gate);
            let blocked = Arc::clone(&blocked);
            workers.push(scope.spawn(move || -> liburing::Result<()> {
                // Each producer observes real backpressure before the consumer runs.
                assert_eq!(queue.push((producer, 0)), Err(UringError::CommandQueueFull));
                blocked.fetch_add(1, Ordering::Relaxed);
                gate.wait();
                for sequence in 0..PER_PRODUCER {
                    loop {
                        deadline(start);
                        match queue.push((producer, sequence)) {
                            Ok(()) => break,
                            Err(UringError::CommandQueueFull) => {
                                blocked.fetch_add(1, Ordering::Relaxed);
                                thread::yield_now();
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                Ok(())
            }));
        }
        gate.wait();
        let mut expected = [0; PRODUCERS + 1];
        let total = PRODUCERS * PER_PRODUCER + queue.capacity();
        let mut consumed = 0;
        let mut batches = 0;
        while consumed < total {
            deadline(start);
            let harvested =
                proactor.wait_completions(1, Some(Duration::from_secs(2)), |_, _| Ok(()))?;
            assert!(
                harvested > 0,
                "accepted commands failed to wake the kernel poll"
            );
            consumed += queue.drain_with(|(producer, sequence)| {
                assert!(producer <= PRODUCERS);
                assert_eq!(
                    sequence, expected[producer],
                    "producer FIFO or exactly-once violation"
                );
                expected[producer] += 1;
            });
            batches += 1;
        }
        for worker in workers {
            worker.join().expect("waker producer panicked")?;
        }
        assert_eq!(&expected[..PRODUCERS], &[PER_PRODUCER; PRODUCERS]);
        assert_eq!(expected[PRODUCERS], queue.capacity());
        assert!(blocked.load(Ordering::Relaxed) >= PRODUCERS);
        assert!(batches > 0);
        assert_eq!(queue.drain_with(|_| panic!("duplicate command")), 0);
        Ok(())
    })?;
    proactor.shutdown()?;
    assert_eq!(queue.push((0, PER_PRODUCER)), Err(UringError::WakerClosed));
    Ok(())
}
