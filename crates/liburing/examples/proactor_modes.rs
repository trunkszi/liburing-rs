//! Four `ProactorMode` loops on one owner thread.
//!
//! Event-driven mode blocks in the kernel. SQPOLL spins on `tick` and keeps
//! warm `enter_calls` unchanged while the kernel SQ thread stays awake. IOPOLL rings
//! are opened and shut down without a blocking wait.

use core::num::NonZeroU32;
use std::time::{Duration, Instant};

use liburing::{
    Completion, EventDrivenConfig, OperationId, OperationPayload, Proactor, ProactorMode, Result,
    SqPollConfig, SubmissionContext, SubsystemId, UringError,
};

fn main() -> Result<()> {
    let (_affinity, owner_cpu, sq_cpu) = Affinity::pin_pair()?;
    println!("mode CPUs owner={owner_cpu} sq_poll={sq_cpu}");
    event_driven()?;
    sq_poll(sq_cpu)?;
    io_poll()?;
    sq_poll_io_poll(sq_cpu)?;
    println!("proactor modes ok: event-driven sq-poll io-poll sq-poll-io-poll");
    Ok(())
}

fn event_driven() -> Result<()> {
    let mut proactor = Proactor::builder()
        .entries(64)
        .event_driven(EventDrivenConfig {
            no_iowait: true,
            batch_wait_usec: NonZeroU32::new(50),
        })
        .build()?;
    assert!(proactor.mode().is_event_driven());
    drive_nop(&mut proactor, false, 1)?;
    let stats = proactor.stats();
    assert!(stats.wait_calls >= 1, "event-driven wait did not block");
    shutdown(&mut proactor)?;
    report_stats("event-driven nop", &proactor);
    Ok(())
}

fn sq_poll(sq_cpu: u32) -> Result<()> {
    let mut proactor = Proactor::builder()
        .entries(128)
        .cq_entries(1024)
        .sq_poll(SqPollConfig::pinned(sq_cpu))
        .build()?;
    assert!(proactor.kernel_features().sq_poll());
    assert_eq!(proactor.mode().name(), "sq-poll");
    reject_blocking_wait(&mut proactor)?;
    drive_nop(&mut proactor, true, 1)?;
    let baseline_enters = proactor.stats().enter_calls;
    for payload in 2..66 {
        drive_nop(&mut proactor, true, payload)?;
    }
    let warm_enter_delta = proactor.stats().enter_calls - baseline_enters;
    assert_eq!(warm_enter_delta, 0, "warm sq-poll nop entered the kernel");
    shutdown(&mut proactor)?;
    println!("sq-poll warm_enter_delta={warm_enter_delta}");
    report_stats("sq-poll lifecycle totals", &proactor);
    Ok(())
}

fn io_poll() -> Result<()> {
    let mut proactor = Proactor::builder().entries(64).io_poll().build()?;
    assert!(proactor.kernel_features().io_poll());
    assert!(proactor.mode().uses_iopoll());
    assert!(!proactor.mode().supports_sockets_and_timers());
    let idle = proactor.stats().enter_calls;
    proactor.tick(&mut ignore)?;
    assert_eq!(proactor.stats().enter_calls, idle);
    shutdown(&mut proactor)?;
    report_stats("io-poll shutdown", &proactor);
    Ok(())
}

fn sq_poll_io_poll(sq_cpu: u32) -> Result<()> {
    let mut proactor = Proactor::builder()
        .entries(64)
        .sq_poll_io_poll(SqPollConfig::pinned(sq_cpu).with_idle_ms(NonZeroU32::MAX))
        .build()?;
    assert!(proactor.kernel_features().sq_poll());
    assert!(proactor.kernel_features().io_poll());
    assert_eq!(proactor.mode(), ProactorMode::sq_poll_io_poll(sq_cpu));
    shutdown(&mut proactor)?;
    report_stats("sq-poll-io-poll shutdown", &proactor);
    Ok(())
}

fn reject_blocking_wait(proactor: &mut Proactor) -> Result<()> {
    let before = proactor.stats().enter_calls;
    let mut called = false;
    let error = proactor.wait_completions(
        1,
        Some(Duration::from_millis(1)),
        &mut |_completion: Completion, _context: &mut SubmissionContext<'_>| {
            called = true;
            Ok(())
        },
    );
    match error {
        Err(UringError::BlockingWaitUnavailable { mode }) => {
            assert_eq!(mode, "sq-poll");
        }
        Ok(_) => return Err(UringError::InvalidConfig("blocking wait was accepted")),
        Err(error) => return Err(error),
    }
    assert!(!called, "rejected wait ran a completion callback");
    assert_eq!(proactor.stats().enter_calls, before);
    Ok(())
}

fn drive_nop(proactor: &mut Proactor, spin: bool, payload: u64) -> Result<()> {
    let id = OperationId::pack(
        SubsystemId::new_unchecked(1),
        OperationPayload::new_unchecked(payload),
    );
    proactor.alloc_sqe(id)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut seen = false;
        let mut dispatch = |completion: Completion, _context: &mut SubmissionContext<'_>| {
            seen = completion.result == 0;
            if completion.result != 0 {
                return Err(UringError::Wait(completion.result.saturating_neg()));
            }
            Ok(())
        };
        if spin {
            proactor.tick(&mut dispatch)?;
        } else {
            proactor.wait_completions(1, Some(Duration::from_millis(50)), &mut dispatch)?;
        }
        if seen {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(UringError::Wait(libc::ETIMEDOUT));
        }
        if spin {
            core::hint::spin_loop();
        }
    }
}

fn shutdown(proactor: &mut Proactor) -> Result<()> {
    proactor.shutdown_with(&mut ignore)
}

fn ignore(_completion: Completion, _context: &mut SubmissionContext<'_>) -> Result<()> {
    Ok(())
}

fn report_stats(label: &str, proactor: &Proactor) {
    let stats = proactor.stats();
    println!(
        "{label} enter_calls={} wait_calls={} sq_wakeups={} cq_overflow_flushes={} \
         sq_full_events={}",
        stats.enter_calls,
        stats.wait_calls,
        stats.sq_wakeups,
        stats.cq_overflow_flushes,
        stats.sq_full_events,
    );
}

struct Affinity {
    original: Vec<usize>,
}

impl Affinity {
    fn pin_pair() -> liburing::Result<(Self, u32, u32)> {
        let mut mask = vec![0usize; 16];
        loop {
            // SAFETY: The aligned initialized mask covers the writable byte extent.
            // pid zero queries this owner thread and no pointer escapes the call.
            if unsafe {
                libc::sched_getaffinity(
                    0,
                    std::mem::size_of_val(mask.as_slice()),
                    mask.as_mut_ptr().cast(),
                )
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) || mask.len() >= 1 << 14 {
                return Err(error.into());
            }
            mask.resize(mask.len() * 2, 0);
        }
        let mut cpus = mask.iter().enumerate().flat_map(|(index, word)| {
            (0..usize::BITS).filter_map(move |bit| {
                (word & (1usize << bit) != 0)
                    .then_some((index * usize::BITS as usize + bit as usize) as u32)
            })
        });
        let (Some(owner), Some(sq_cpu)) = (cpus.next(), cpus.next()) else {
            return Err(liburing::UringError::InvalidConfig(
                "SQPOLL examples and benchmarks require two allowed CPUs",
            ));
        };
        let mut pinned = vec![0usize; mask.len()];
        pinned[owner as usize / usize::BITS as usize] = 1usize << (owner % usize::BITS);
        let guard = Self { original: mask };
        // SAFETY: The word-aligned readable mask spans the supplied byte extent.
        // The selected owner CPU belongs to the captured mask of this thread.
        if unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(pinned.as_slice()),
                pinned.as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((guard, owner, sq_cpu))
    }
}

impl Drop for Affinity {
    fn drop(&mut self) {
        // SAFETY: The captured initialized mask remains readable for its full
        // extent and restores only this calling thread's original affinity.
        let restored = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of_val(self.original.as_slice()),
                self.original.as_ptr().cast(),
            )
        };
        assert_eq!(
            restored,
            0,
            "affinity restoration failed: {}",
            std::io::Error::last_os_error()
        );
    }
}
