//! Fixed-budget caller identity lookup without resizing or tombstones.

use crate::{OperationId, Result, UringError, operation_slab::OperationKey};

const EMPTY_KEY: u64 = u64::MAX;

/// A preallocated linear-probe table at most half occupied.
/// Keys and values have equal, immutable lengths; mask is their power-of-two length minus one.
pub(crate) struct IdentityMap {
    keys: Box<[u64]>,
    vals: Box<[OperationKey]>,
    mask: usize,
    capacity: usize,
    len: usize,
}

impl IdentityMap {
    /// Allocates a fixed power-of-two table for the logical operation budget.
    ///
    /// # Errors
    /// Returns an error for a zero or overflowing budget or allocation failure.
    ///
    /// # Panics
    /// Does not panic.
    pub(crate) fn new(capacity: usize) -> Result<Self> {
        let slots = capacity
            .checked_mul(2)
            .filter(|_| capacity != 0)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(UringError::InvalidConfig("identity capacity is invalid"))?;
        let mut keys = Vec::new();
        let mut vals = Vec::new();
        keys.try_reserve_exact(slots)
            .map_err(|_| UringError::InvalidConfig("identity allocation failed"))?;
        vals.try_reserve_exact(slots)
            .map_err(|_| UringError::InvalidConfig("identity allocation failed"))?;
        keys.resize(slots, EMPTY_KEY);
        vals.resize(
            slots,
            OperationKey::from_payload(crate::OperationPayload(1 << 24))?,
        );
        Ok(Self {
            keys: keys.into_boxed_slice(),
            vals: vals.into_boxed_slice(),
            mask: slots - 1,
            capacity,
            len: 0,
        })
    }

    /// Looks up an operation key without allocating or changing table state.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline(always)]
    pub(crate) fn get(&self, id: &OperationId) -> Option<&OperationKey> {
        let index = self.find(*id)?;
        // SAFETY: find returns a key index; the equally sized value allocation never resizes.
        Some(unsafe { self.vals.get_unchecked(index) })
    }

    /// Reports whether this exact caller identity is currently occupied.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[cfg(test)]
    #[inline]
    pub(crate) fn contains_key(&self, id: &OperationId) -> bool {
        self.find(*id).is_some()
    }

    /// Inserts a new identity without replacing existing metadata or growing.
    ///
    /// # Errors
    /// Returns InvalidPayload for a duplicate or reserved ID, and SqRingFull at logical capacity.
    /// Rejection preserves every existing entry and the occupied count.
    ///
    /// # Panics
    /// Does not panic.
    #[cfg(test)]
    #[inline]
    pub(crate) fn insert(&mut self, id: OperationId, key: OperationKey) -> Result<()> {
        let slot = self.probe_vacant(id)?;
        self.insert_at(slot, id, key);
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn probe_vacant(&self, id: OperationId) -> Result<usize> {
        let raw = id.raw();
        if raw == EMPTY_KEY {
            return Err(UringError::InvalidPayload(raw));
        }
        let mut index = self.bucket(id);
        loop {
            // SAFETY: bucket and next mask every probe into the fixed key allocation.
            let stored = unsafe { *self.keys.get_unchecked(index) };
            if stored == raw {
                return Err(UringError::InvalidPayload(raw));
            }
            if stored == EMPTY_KEY {
                if self.len == self.capacity {
                    return Err(UringError::SqRingFull);
                }
                return Ok(index);
            }
            index = self.next(index);
        }
    }

    // The caller retains exclusive access from the side-effect-free probe through insertion.
    #[inline(always)]
    pub(crate) fn insert_at(&mut self, slot: usize, id: OperationId, key: OperationKey) {
        self.keys[slot] = id.raw();
        self.vals[slot] = key;
        self.len += 1;
    }

    /// Removes an identity and closes probe-chain holes without tombstones.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    // Keep the deletion loop out of each monomorphized dispatcher to bound instruction footprint.
    #[inline(never)]
    pub(crate) fn remove(&mut self, id: &OperationId) -> Option<OperationKey> {
        let mut hole = self.find(*id)?;
        // SAFETY: find establishes the initial hole; next and bucket mask all subsequent
        // indices into fixed, equally sized key/value arrays. Moving entries cannot resize them.
        unsafe {
            let removed = *self.vals.get_unchecked(hole);
            *self.keys.get_unchecked_mut(hole) = EMPTY_KEY;
            self.len -= 1;
            let mask = self.mask;
            let mut cursor = self.next(hole);
            while *self.keys.get_unchecked(cursor) != EMPTY_KEY {
                let home = self.bucket(OperationId::from_raw(*self.keys.get_unchecked(cursor)));
                // Move only entries whose original probe crossed this vacancy.
                // Wrapping distances also cover chains crossing the array boundary.
                if (cursor.wrapping_sub(home) & mask) >= (hole.wrapping_sub(home) & mask) {
                    *self.keys.get_unchecked_mut(hole) = *self.keys.get_unchecked(cursor);
                    *self.vals.get_unchecked_mut(hole) = *self.vals.get_unchecked(cursor);
                    *self.keys.get_unchecked_mut(cursor) = EMPTY_KEY;
                    hole = cursor;
                }
                cursor = self.next(cursor);
            }
            Some(removed)
        }
    }

    /// Returns occupied logical entries, excluding spare probe storage.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[cfg(test)]
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn find(&self, id: OperationId) -> Option<usize> {
        let keys = self.keys.as_ref();
        let mask = self.mask;
        let raw = id.raw();
        if raw == EMPTY_KEY {
            return None;
        }
        let mut index = self.bucket(id);
        loop {
            // SAFETY: bucket and the masked increment stay within this fixed key slice.
            let stored = unsafe { *keys.get_unchecked(index) };
            if stored == raw {
                return Some(index);
            }
            if stored == EMPTY_KEY {
                return None;
            }
            index = (index + 1) & mask;
        }
    }

    #[inline(always)]
    fn next(&self, index: usize) -> usize {
        (index + 1) & self.mask
    }

    #[inline(always)]
    fn bucket(&self, id: OperationId) -> usize {
        // SplitMix64's finalizer spreads both routing and payload bits before
        // masking into a fixed power-of-two table. No random state is required.
        let mut value = id.raw();
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((value ^ (value >> 31)) as usize) & self.mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationPayload;

    fn key(value: u64) -> Result<OperationKey> {
        OperationKey::from_payload(OperationPayload::new_unchecked((1 << 24) | value))
    }

    fn occupancy(map: &IdentityMap) {
        assert_eq!(
            map.keys.iter().filter(|&&key| key != EMPTY_KEY).count(),
            map.len()
        );
        assert_eq!(map.keys.len(), map.vals.len());
        assert!(map.len() <= map.capacity);
        assert!(map.keys.len() >= 2 * map.capacity);
        assert!(map.keys.len().is_power_of_two());
    }

    #[test]
    fn sentinel_rejection_preserves_capacity() -> Result<()> {
        let mut map = IdentityMap::new(1)?;
        let sentinel = OperationId::from_raw(u64::MAX);
        assert_eq!(
            map.insert(sentinel, key(0)?),
            Err(UringError::InvalidPayload(u64::MAX))
        );
        assert_eq!(map.get(&sentinel), None);
        assert_eq!(map.remove(&sentinel), None);
        assert_eq!(map.len(), 0);
        map.insert(OperationId::from_raw(0), key(1)?)?;
        assert_eq!(map.get(&OperationId::from_raw(0)), Some(&key(1)?));
        Ok(())
    }

    #[test]
    fn collision_chain_survives_deletion() -> Result<()> {
        let mut map = IdentityMap::new(4)?;
        let mut ids = Vec::new();
        for raw in 0..1024 {
            let id = OperationId::from_raw(raw);
            if map.bucket(id) == map.keys.len() - 1 {
                ids.push(id);
            }
            if ids.len() == 4 {
                break;
            }
        }
        assert_eq!(ids.len(), 4);
        for (index, id) in ids.iter().copied().enumerate() {
            map.insert(id, key(index as u64)?)?;
        }
        assert_eq!(map.keys[7], ids[0].raw());
        assert_eq!(map.keys[0], ids[1].raw());
        assert_eq!(map.remove(&ids[1]), Some(key(1)?));
        assert_eq!(map.get(&ids[2]), Some(&key(2)?));
        assert_eq!(map.get(&ids[3]), Some(&key(3)?));
        assert!(!map.contains_key(&ids[1]));
        occupancy(&map);
        assert_eq!(map.remove(&ids[0]), Some(key(0)?));
        for (index, id) in ids.iter().enumerate().skip(2) {
            assert_eq!(map.get(id), Some(&key(index as u64)?));
        }
        assert_eq!(map.remove(&ids[2]), Some(key(2)?));
        assert_eq!(map.remove(&ids[3]), Some(key(3)?));
        assert_eq!(map.len(), 0);
        occupancy(&map);
        Ok(())
    }

    #[test]
    fn rejection_preserves_map_entries() -> Result<()> {
        let mut map = IdentityMap::new(3)?;
        for raw in 0..3 {
            map.insert(OperationId::from_raw(raw), key(raw)?)?;
        }
        let before = (map.keys.clone(), map.vals.clone());
        assert_eq!(
            map.insert(OperationId::from_raw(1), key(77)?),
            Err(UringError::InvalidPayload(1))
        );
        assert_eq!(
            map.insert(OperationId::from_raw(3), key(3)?),
            Err(UringError::SqRingFull)
        );
        assert_eq!(map.remove(&OperationId::from_raw(99)), None);
        assert_eq!((&map.keys, &map.vals), (&before.0, &before.1));
        for raw in 0..3 {
            assert_eq!(map.get(&OperationId::from_raw(raw)), Some(&key(raw)?));
        }
        occupancy(&map);
        assert_eq!(map.remove(&OperationId::from_raw(1)), Some(key(1)?));
        map.insert(OperationId::from_raw(3), key(3)?)?;
        occupancy(&map);
        assert!(IdentityMap::new(0).is_err());
        assert!(IdentityMap::new(usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn repeated_reuse_preserves_storage() -> Result<()> {
        let mut map = IdentityMap::new(32)?;
        let address = (map.keys.as_ptr(), map.vals.as_ptr());
        let storage = map.keys.len();
        for raw in 0..32 {
            map.insert(OperationId::from_raw(raw), key(raw)?)?;
        }
        for raw in 32..100_032 {
            assert_eq!(
                map.remove(&OperationId::from_raw(raw - 32)),
                Some(key(raw - 32)?)
            );
            map.insert(OperationId::from_raw(raw), key(raw)?)?;
            assert_eq!(map.get(&OperationId::from_raw(raw)), Some(&key(raw)?));
            assert_eq!(map.len(), 32);
            assert_eq!((map.keys.as_ptr(), map.vals.as_ptr()), address);
            assert_eq!(map.keys.len(), storage);
            occupancy(&map);
        }
        for raw in 100_000..100_032 {
            assert_eq!(map.get(&OperationId::from_raw(raw)), Some(&key(raw)?));
        }
        Ok(())
    }

    #[test]
    fn mixed_buckets_survive_removal() -> Result<()> {
        let mut map = IdentityMap::new(64)?;
        for epoch in 0..100 {
            for index in 0..64 {
                let raw = epoch * 64 + index;
                map.insert(OperationId::from_raw(raw), key(raw)?)?;
            }
            for index in 0..64 {
                let removed = (index * 37) % 64;
                let raw = epoch * 64 + removed;
                assert_eq!(map.remove(&OperationId::from_raw(raw)), Some(key(raw)?));
                for later in index + 1..64 {
                    let retained = epoch * 64 + (later * 37) % 64;
                    assert_eq!(
                        map.get(&OperationId::from_raw(retained)),
                        Some(&key(retained)?)
                    );
                }
                occupancy(&map);
            }
            assert_eq!(map.len(), 0);
        }
        Ok(())
    }
}
