//! Shared eventfd wakeups and bounded cross-thread command delivery.

use std::{
    collections::VecDeque,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::error::{Result, UringError};

struct WakeState {
    fd: OwnedFd,
    closed: AtomicBool,
}

/// A cloneable thread-safe endpoint waking a single proactor through eventfd.
///
/// Wakeups coalesce. A successful wake guarantees readiness, not a separate CQE
/// for each caller. Closing the endpoint rejects new wakeups on every clone.
#[derive(Clone)]
pub struct ProactorWaker {
    state: Arc<WakeState>,
}

impl ProactorWaker {
    /// Create a nonblocking close-on-exec eventfd.
    ///
    /// # Errors
    /// Returns [`UringError::WakerSetup`] with the positive errno on failure.
    ///
    /// # Panics
    /// This function does not panic except on allocation failure.
    pub fn new() -> Result<Self> {
        // SAFETY: eventfd has no pointer arguments and these flags are valid.
        let raw_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw_fd < 0 {
            return Err(UringError::WakerSetup(last_errno()));
        }
        // SAFETY: Successful eventfd returned a fresh descriptor owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self {
            state: Arc::new(WakeState {
                fd,
                closed: AtomicBool::new(false),
            }),
        })
    }

    /// Make the owning proactor ready without blocking the calling thread.
    ///
    /// Eventfd counter saturation already represents a pending wake and succeeds.
    ///
    /// # Errors
    /// Returns [`UringError::WakerClosed`] after closure or a structured syscall
    /// error if the kernel rejects the write.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn wake(&self) -> Result<()> {
        if self.is_closed() {
            return Err(UringError::WakerClosed);
        }
        let increment = 1_u64;
        loop {
            // SAFETY: The shared state retains fd for this call; increment is a
            // valid initialized eight-byte source for the synchronous write.
            let written = unsafe {
                libc::write(
                    self.raw_fd(),
                    (&raw const increment).cast(),
                    core::mem::size_of::<u64>(),
                )
            };
            if written == 8 {
                return Ok(());
            }
            let errno = if written < 0 { last_errno() } else { libc::EIO };
            match errno {
                libc::EINTR => continue,
                libc::EAGAIN => return Ok(()),
                _ => {
                    return Err(UringError::Syscall {
                        op: "eventfd write",
                        errno,
                    });
                }
            }
        }
    }

    /// Return the borrowed descriptor used to arm an io_uring poll operation.
    ///
    /// The descriptor remains owned by this endpoint and must not be closed by
    /// callers. Retain a clone until all poll operations on it have completed.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.state.fd.as_raw_fd()
    }

    /// Consume pending eventfd readiness without waiting for another producer.
    ///
    /// The proactor calls this after its one-shot poll CQE and rearms the poll.
    ///
    /// # Errors
    /// Returns a structured syscall error if the eventfd read fails.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn drain(&self) -> Result<()> {
        loop {
            let mut count = 0_u64;
            // SAFETY: count is writable for eight bytes and fd remains owned by
            // shared state throughout this synchronous nonblocking read.
            let read = unsafe {
                libc::read(
                    self.raw_fd(),
                    (&raw mut count).cast(),
                    core::mem::size_of::<u64>(),
                )
            };
            if read == 8 {
                return Ok(());
            }
            let errno = if read < 0 { last_errno() } else { libc::EIO };
            match errno {
                libc::EINTR => continue,
                libc::EAGAIN => return Ok(()),
                _ => {
                    return Err(UringError::Syscall {
                        op: "eventfd read",
                        errno,
                    });
                }
            }
        }
    }

    /// Reject future wakes while retaining the descriptor for outstanding polls.
    ///
    /// The final endpoint clone closes the descriptor through its owned handle.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
    }

    /// Return whether the owning proactor has closed this endpoint.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }
}

struct CommandState<T> {
    commands: Mutex<VecDeque<T>>,
    capacity: usize,
    waker: ProactorWaker,
}

/// A bounded command mailbox for control-plane producers on other threads.
///
/// The queue allocates its capacity once and serializes producers and consumers
/// with a mutex. Use it for control-plane work outside latency-sensitive I/O
/// callbacks. Each accepted command makes the shared waker ready.
pub struct CrossThreadCommandQueue<T> {
    state: Arc<CommandState<T>>,
}

impl<T> Clone for CrossThreadCommandQueue<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<T> CrossThreadCommandQueue<T> {
    /// Construct a queue with exactly `capacity` command slots.
    ///
    /// A zero-capacity queue rejects all pushes. The supplied wake endpoint must
    /// belong to the proactor that consumes the commands.
    ///
    /// # Panics
    /// Panics if the requested allocation exceeds the addressable capacity.
    #[must_use]
    pub fn new(capacity: usize, waker: ProactorWaker) -> Self {
        Self {
            state: Arc::new(CommandState {
                commands: Mutex::new(VecDeque::with_capacity(capacity)),
                capacity,
                waker,
            }),
        }
    }

    /// Enqueue a command and notify the consuming proactor.
    ///
    /// # Errors
    /// Returns [`UringError::CommandQueueFull`] if the mailbox is full,
    /// [`UringError::WakerClosed`] if its endpoint was closed, or a structured
    /// error for a poisoned mutex or failed wake. On error no command is added.
    ///
    /// # Panics
    /// Propagates a panic from the command's destructor on a rejected wake.
    pub fn push(&self, command: T) -> Result<()> {
        let mut commands = self.state.commands.lock().map_err(|_| poisoned_queue())?;
        if self.state.waker.is_closed() {
            return Err(UringError::WakerClosed);
        }
        if commands.len() >= self.state.capacity {
            return Err(UringError::CommandQueueFull);
        }
        commands.push_back(command);
        if let Err(error) = self.state.waker.wake() {
            let rejected = commands.pop_back();
            drop(commands);
            drop(rejected);
            return Err(error);
        }
        Ok(())
    }

    /// Remove the oldest queued command, if present.
    ///
    /// Commands accepted before endpoint closure remain available to drain.
    /// Wakeups coalesce, and the proactor consumes eventfd readiness separately
    /// from commands. After each wake, call `pop` until it returns `Ok(None)`
    /// (for example, `while let Some(command) = queue.pop()? { /* handle */ }`)
    /// or use [`Self::drain_with`]; consuming only one command can strand others.
    ///
    /// # Errors
    /// Returns a structured error if the queue mutex was poisoned.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn pop(&self) -> Result<Option<T>> {
        let mut commands = self.state.commands.lock().map_err(|_| poisoned_queue())?;
        Ok(commands.pop_front())
    }

    /// Consume commands in FIFO order until the queue is observed empty.
    ///
    /// Calls `f` without holding the queue mutex, so it may enqueue follow-up
    /// commands. These commands are also consumed before returning if no empty
    /// queue is observed first. Continuous producers can keep this call running.
    /// Returns the number of commands delivered to `f`.
    ///
    /// # Errors
    /// This function does not return errors. It recovers a poisoned mutex to
    /// drain the still-valid queue; it does not clear the poison flag.
    ///
    /// # Panics
    /// Propagates a panic from `f`. Its command has been removed; later commands
    /// remain queued, and the callback cannot poison the queue mutex.
    pub fn drain_with<F: FnMut(T)>(&self, mut f: F) -> usize {
        let mut count = 0;
        loop {
            let command = {
                let mut commands = match self.state.commands.lock() {
                    Ok(commands) => commands,
                    Err(poisoned) => poisoned.into_inner(),
                };
                commands.pop_front()
            };
            let Some(command) = command else {
                return count;
            };
            f(command);
            count += 1;
        }
    }

    /// Return the queue's fixed number of command slots.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.state.capacity
    }

    /// Return the number of commands currently waiting for consumption.
    ///
    /// # Errors
    /// Returns a structured error if the queue mutex was poisoned.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn len(&self) -> Result<usize> {
        let commands = self.state.commands.lock().map_err(|_| poisoned_queue())?;
        Ok(commands.len())
    }

    /// Return whether there are no queued commands.
    ///
    /// # Errors
    /// Returns a structured error if the queue mutex was poisoned.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

fn poisoned_queue() -> UringError {
    UringError::Syscall {
        op: "command queue lock",
        errno: libc::EOWNERDEAD,
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod integration_lifecycle_scenario_tests {
    use super::*;

    #[test]
    fn drain_consumes_coalesced_commands_and_reentrant_pushes_in_fifo_order() -> Result<()> {
        let waker = ProactorWaker::new()?;
        let queue = CrossThreadCommandQueue::new(2, waker.clone());
        queue.push(1)?;
        queue.push(2)?;
        waker.drain()?;
        let mut received = Vec::new();
        let mut push_error = None;
        let count = queue.drain_with(|command| {
            received.push(command);
            if command == 1 {
                push_error = queue.push(3).err();
            }
        });
        assert_eq!(push_error, None);
        assert_eq!(received, [1, 2, 3]);
        assert_eq!(count, 3);
        assert!(queue.is_empty()?);
        assert_eq!(
            queue.drain_with(|_| panic!("empty queue invoked callback")),
            0
        );
        Ok(())
    }

    #[test]
    fn drain_callback_panic_preserves_remaining_commands_and_mutex() -> Result<()> {
        let queue = CrossThreadCommandQueue::new(2, ProactorWaker::new()?);
        queue.push(1)?;
        queue.push(2)?;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            queue.drain_with(|_| panic!("controlled command callback panic"))
        }));
        assert!(unwound.is_err());
        assert_eq!(queue.pop()?, Some(2));
        queue.push(3)?;
        assert_eq!(queue.pop()?, Some(3));
        Ok(())
    }

    #[test]
    fn drain_recovers_commands_from_poisoned_mutex() -> Result<()> {
        let queue = CrossThreadCommandQueue::new(1, ProactorWaker::new()?);
        queue.push(7)?;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _commands = queue.state.commands.lock();
            panic!("controlled queue mutex poison");
        }));
        assert!(unwound.is_err());
        assert_eq!(queue.pop(), Err(poisoned_queue()));
        let mut received = Vec::new();
        assert_eq!(queue.drain_with(|command| received.push(command)), 1);
        assert_eq!(received, [7]);
        assert_eq!(queue.drain_with(drop), 0);
        Ok(())
    }

    #[test]
    fn bounded_queue_preserves_order_and_drains_after_endpoint_closure() -> Result<()> {
        let waker = ProactorWaker::new()?;
        let queue = CrossThreadCommandQueue::new(2, waker.clone());
        queue.push(11)?;
        queue.push(23)?;
        assert_eq!(queue.push(37), Err(UringError::CommandQueueFull));
        assert_eq!(queue.len()?, 2);
        waker.drain()?;
        waker.close();
        assert_eq!(queue.push(41), Err(UringError::WakerClosed));
        assert_eq!(queue.pop()?, Some(11));
        assert_eq!(queue.pop()?, Some(23));
        assert_eq!(queue.pop()?, None);
        assert_eq!(waker.wake(), Err(UringError::WakerClosed));
        Ok(())
    }

    #[test]
    fn producer_thread_publishes_command_and_eventfd_readiness() -> Result<()> {
        let waker = ProactorWaker::new()?;
        let queue = CrossThreadCommandQueue::new(1, waker.clone());
        let producer_queue = queue.clone();
        let producer = std::thread::spawn(move || producer_queue.push(83));
        let result = producer.join().map_err(|_| UringError::Syscall {
            op: "command producer join",
            errno: libc::ECANCELED,
        })?;
        result?;
        let mut poll_fd = libc::pollfd {
            fd: waker.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd is one initialized writable pollfd; zero timeout cannot
        // block and its eventfd remains alive through waker's shared state.
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, 0) };
        assert_eq!(ready, 1);
        assert_ne!(poll_fd.revents & libc::POLLIN, 0);
        assert_eq!(queue.pop()?, Some(83));
        waker.drain()?;
        // SAFETY: The same initialized live descriptor and pollfd remain valid.
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, 0) };
        assert_eq!(ready, 0);
        Ok(())
    }
}
