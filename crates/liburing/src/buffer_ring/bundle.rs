//! Allocation-free bundle handoff in descriptor publication order.
use super::{BufferId, BufferLease, BufferRing, Result, invalid, kernel_error};

impl BufferRing {
    /// Leases all buffers consumed by a RECVSEND_BUNDLE completion into caller storage.
    ///
    /// Entries follow descriptor publication order, which can differ from numeric bid
    /// order after out-of-order returns. Each lease recycles independently. Bundle and
    /// incremental consumption must use separate groups. On error output is unchanged.
    /// # Errors
    /// Rejects inactive/incremental groups, invalid flags, lengths, selected IDs,
    /// occupied descriptors, nonempty output slots or insufficient output capacity.
    /// Negative completions return their kernel error without transferring ownership.
    /// # Panics
    /// Does not panic for valid completion metadata.
    /// # Safety
    /// Pass each actual bundle CQE exactly once in CQ order, from an operation
    /// selecting this group. The CQE must release all consumed descriptors and
    /// initialize exactly `result` bytes in publication order. No kernel access
    /// to those ranges may remain. Error CQEs with selected buffers must instead
    /// be passed to `lease_from_cqe` to recycle their individual selection.
    pub unsafe fn lease_bundle_from_cqe<'a>(
        &'a self,
        flags: u32,
        result: i32,
        output: &mut [Option<BufferLease<'a>>],
    ) -> Result<usize> {
        if !self.registered || self.incremental || flags & (1 << 4) != 0 {
            return Err(invalid("bundle requires an active nonincremental group"));
        }
        if result < 0 {
            return Err(kernel_error(result));
        }
        let first = Self::buffer_id_from_flags(flags)
            .filter(|id| id.0 < self.entries)
            .ok_or_else(|| invalid("invalid bundle buffer ID"))?;
        let position = self.progress[usize::from(first.0)].position.get();
        let mut left = result as usize;
        let mut count = 0;
        loop {
            if count >= usize::from(self.entries) || count >= output.len() {
                return Err(invalid("bundle exceeds group or output capacity"));
            }
            let slot = position.wrapping_add(count as u16);
            let id = self.buffer_ring.id_at(slot, self.entries - 1);
            if id >= self.entries || output[count].is_some() {
                return Err(invalid("invalid bundle descriptor or occupied output"));
            }
            let index = usize::from(id);
            if self.progress[index].position.get() != slot
                || self.leased_bits[index >> 6].get().test((index & 63) as u32)
            {
                return Err(invalid(
                    "bundle descriptor is already leased or overwritten",
                ));
            }
            count += 1;
            left = left.saturating_sub(self.buffer_len as usize);
            if left == 0 {
                break;
            }
        }
        left = result as usize;
        for (offset, output) in output[..count].iter_mut().enumerate() {
            let id = self
                .buffer_ring
                .id_at(position.wrapping_add(offset as u16), self.entries - 1);
            let index = usize::from(id);
            let len = left.min(self.buffer_len as usize);
            let bits = &self.leased_bits[index >> 6];
            bits.set(bits.get().set((index & 63) as u32));
            let progress = &self.progress[index];
            progress.leases.set(1);
            progress.offset.set(len as u32);
            progress.kernel_done.set(true);
            *output = Some(BufferLease {
                owner: self,
                id: BufferId(id),
                offset: 0,
                len,
            });
            left -= len;
        }
        Ok(count)
    }
}
