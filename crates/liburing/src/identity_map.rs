//! Fixed-budget caller identity lookup without resizing or tombstones.

use crate::{OperationId, Result, UringError, operation_slab::OperationKey};

/// A preallocated linear-probe table at most half occupied.
pub(crate) struct IdentityMap {
    entries: Box<[Option<(OperationId, OperationKey)>]>,
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
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(slots)
            .map_err(|_| UringError::InvalidConfig("identity allocation failed"))?;
        entries.resize(slots, None);
        Ok(Self {
            entries: entries.into_boxed_slice(),
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
        self.entries[index].as_ref().map(|(_, key)| key)
    }

    /// Reports whether this exact caller identity is currently occupied.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    pub(crate) fn contains_key(&self, id: &OperationId) -> bool {
        self.find(*id).is_some()
    }

    /// Inserts a new identity without replacing existing metadata or growing.
    ///
    /// # Errors
    /// Returns InvalidPayload for a duplicate and SqRingFull at logical capacity.
    /// Rejection preserves every existing entry and the occupied count.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub(crate) fn insert(&mut self, id: OperationId, key: OperationKey) -> Result<()> {
        let mut index = self.bucket(id);
        loop {
            match self.entries[index] {
                Some((identity, _)) if identity == id => {
                    return Err(UringError::InvalidPayload(id.raw()));
                }
                Some(_) => index = self.next(index),
                None => break,
            }
        }
        if self.len == self.capacity {
            return Err(UringError::SqRingFull);
        }
        self.entries[index] = Some((id, key));
        self.len += 1;
        Ok(())
    }

    /// Removes an identity and closes probe-chain holes without tombstones.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[inline]
    pub(crate) fn remove(&mut self, id: &OperationId) -> Option<OperationKey> {
        let mut hole = self.find(*id)?;
        let (_, removed) = self.entries[hole].take()?;
        self.len -= 1;
        let mask = self.mask;
        let mut cursor = self.next(hole);
        while let Some((identity, _)) = self.entries[cursor] {
            let home = self.bucket(identity);
            // Move only entries whose original probe crossed this vacancy.
            // Wrapping distances also cover chains crossing the array boundary.
            if (cursor.wrapping_sub(home) & mask) >= (hole.wrapping_sub(home) & mask) {
                self.entries[hole] = self.entries[cursor].take();
                hole = cursor;
            }
            cursor = self.next(cursor);
        }
        Some(removed)
    }

    /// Returns occupied logical entries, excluding spare probe storage.
    ///
    /// # Errors
    /// Does not return errors.
    ///
    /// # Panics
    /// Does not panic.
    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn find(&self, id: OperationId) -> Option<usize> {
        let entries = self.entries.as_ref();
        let mask = self.mask;
        let raw = id.raw();
        let mut index = self.bucket(id);
        loop {
            match entries[index] {
                Some((identity, _)) if identity.raw() == raw => return Some(index),
                Some(_) => index = (index + 1) & mask,
                None => return None,
            }
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
            map.entries.iter().filter(|entry| entry.is_some()).count(),
            map.len()
        );
        assert!(map.len() <= map.capacity);
        assert!(map.entries.len() >= 2 * map.capacity);
        assert!(map.entries.len().is_power_of_two());
    }

    #[test]
    fn middle_and_head_deletion_preserve_wrapping_collision_chains() -> Result<()> {
        let mut map = IdentityMap::new(4)?;
        let mut ids = Vec::new();
        for raw in 0..1024 {
            let id = OperationId::from_raw(raw);
            if map.bucket(id) == map.entries.len() - 1 {
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
        assert_eq!(map.entries[7].map(|(id, _)| id), Some(ids[0]));
        assert_eq!(map.entries[0].map(|(id, _)| id), Some(ids[1]));
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
    fn duplicate_full_and_missing_operations_preserve_entries() -> Result<()> {
        let mut map = IdentityMap::new(3)?;
        for raw in 0..3 {
            map.insert(OperationId::from_raw(raw), key(raw)?)?;
        }
        let before = map.entries.clone();
        assert_eq!(
            map.insert(OperationId::from_raw(1), key(77)?),
            Err(UringError::InvalidPayload(1))
        );
        assert_eq!(
            map.insert(OperationId::from_raw(3), key(3)?),
            Err(UringError::SqRingFull)
        );
        assert_eq!(map.remove(&OperationId::from_raw(99)), None);
        assert_eq!(map.entries, before);
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
    fn one_hundred_thousand_reuses_keep_storage_and_occupancy_fixed() -> Result<()> {
        let mut map = IdentityMap::new(32)?;
        let address = map.entries.as_ptr();
        let storage = map.entries.len();
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
            assert_eq!(map.entries.as_ptr(), address);
            assert_eq!(map.entries.len(), storage);
            occupancy(&map);
        }
        for raw in 100_000..100_032 {
            assert_eq!(map.get(&OperationId::from_raw(raw)), Some(&key(raw)?));
        }
        Ok(())
    }

    #[test]
    fn mixed_home_buckets_survive_arbitrary_removal_order() -> Result<()> {
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
