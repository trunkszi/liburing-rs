//! CPU selection within the calling test thread's allowed affinity mask.

use super::{Result, UringError};

pub(super) fn sq_thread_cpu() -> Result<u32> {
    let mut mask = vec![0usize; 16];
    loop {
        // SAFETY: The aligned initialized mask covers the writable byte extent.
        // pid zero queries only this thread and no pointer escapes the call.
        if unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(mask.as_slice()),
                mask.as_mut_ptr().cast(),
            )
        } == 0
        {
            let mut found = None;
            for (index, word) in mask.iter().enumerate() {
                for bit in 0..usize::BITS {
                    if word & (1usize << bit) != 0 {
                        let cpu = (index * usize::BITS as usize + bit as usize) as u32;
                        if found.is_some() {
                            return Ok(cpu);
                        }
                        found = Some(cpu);
                    }
                }
            }
            return Err(UringError::InvalidConfig(
                "SQPOLL qualification requires two allowed CPUs",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) || mask.len() >= 1 << 14 {
            return Err(error.into());
        }
        mask.resize(mask.len() * 2, 0);
    }
}
