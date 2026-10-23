//! Proactor-owned resource storage, startup registration, and lifetime access.

use super::Proactor;
use crate::{
    BufferGroupId, Result, UringError, buffer_ring::BufferRing, fixed_buffers::FixedBufferPool,
    fixed_files::FixedFileTable,
};

pub(crate) struct Resources {
    pub(crate) buffers: Option<FixedBufferPool>,
    pub(crate) files: Option<FixedFileTable>,
    pub(crate) provided: Vec<BufferRing>,
}

impl Resources {
    pub(crate) fn new(groups: usize) -> Self {
        Self {
            buffers: None,
            files: None,
            provided: Vec::with_capacity(groups),
        }
    }

    pub(crate) fn group(&self, group: BufferGroupId) -> Result<&BufferRing> {
        self.provided
            .iter()
            .find(|pool| pool.group_id() == group)
            .ok_or(UringError::InvalidConfig(
                "provided buffer group is not registered",
            ))
    }
}

impl Proactor {
    pub(crate) fn configure_socket_buffers(
        &mut self,
        count: u16,
        group: BufferGroupId,
        entries: u16,
        length: usize,
    ) -> Result<()> {
        self.configure_fixed_buffers(count, length)?;
        if let Err(error) = self.register_buffer_ring(group, entries, length) {
            if let Some(resources) = self.resources.as_mut() {
                drop(resources.buffers.take());
            }
            return Err(error);
        }
        Ok(())
    }

    /// Allocates the ring's single registered fixed-buffer table.
    /// # Errors
    /// Returns configuration, allocation, or kernel registration errors.
    /// # Panics
    /// Does not intentionally panic.
    pub fn configure_fixed_buffers(&mut self, count: u16, length: usize) -> Result<()> {
        self.ensure_open()?;
        if self
            .resources
            .as_ref()
            .is_some_and(|resources| resources.buffers.is_some())
        {
            return Err(UringError::InvalidConfig(
                "fixed buffers are already configured",
            ));
        }
        // SAFETY: The boxed ring remains stable and owned until all tracked DMA
        // retires; resource tables are dropped before this ring is destroyed.
        let pool = unsafe { FixedBufferPool::new(self.ring_mut(), count, length) }?;
        self.resources
            .as_mut()
            .ok_or(UringError::InvalidConfig("resources are closed"))?
            .buffers = Some(pool);
        Ok(())
    }

    /// Allocates one predeclared provided-buffer group.
    /// # Errors
    /// Returns group capacity, configuration, allocation, or registration errors.
    /// # Panics
    /// Does not intentionally panic.
    pub fn register_buffer_ring(
        &mut self,
        group: BufferGroupId,
        entries: u16,
        length: usize,
    ) -> Result<()> {
        self.ensure_open()?;
        let resources = self
            .resources
            .as_ref()
            .ok_or(UringError::InvalidConfig("resources are closed"))?;
        if resources.provided.len() >= self.config.buffer_groups {
            return Err(UringError::InvalidConfig("provided group budget exhausted"));
        }
        if resources
            .provided
            .iter()
            .any(|pool| pool.group_id() == group)
        {
            return Err(UringError::InvalidConfig(
                "provided group already registered",
            ));
        }
        // SAFETY: Group storage remains owned until all selecting receives retire
        // and all borrowed leases finish, before the stable ring is destroyed.
        let pool = unsafe { BufferRing::new(self.ring_mut(), entries, length, group) }?;
        self.resources
            .as_mut()
            .ok_or(UringError::InvalidConfig("resources are closed"))?
            .provided
            .push(pool);
        Ok(())
    }

    /// Allocates the ring's registered descriptor table.
    /// # Errors
    /// Returns duplicate registration, allocation, or kernel errors.
    /// # Panics
    /// Does not intentionally panic.
    pub fn configure_fixed_files(&mut self, capacity: u32) -> Result<()> {
        self.ensure_open()?;
        if self
            .resources
            .as_ref()
            .is_some_and(|resources| resources.files.is_some())
        {
            return Err(UringError::InvalidConfig(
                "fixed files are already configured",
            ));
        }
        // SAFETY: The table remains owned by the stable ring and is unregistered
        // only after all tracked operations using its slots retire.
        let files = unsafe { FixedFileTable::new(self.ring_mut(), capacity) }?;
        self.resources
            .as_mut()
            .ok_or(UringError::InvalidConfig("resources are closed"))?
            .files = Some(files);
        Ok(())
    }

    /// Borrows a group whose selected payloads remain owned through lease drop.
    /// # Errors
    /// Returns an error for an unregistered group or closed ring.
    /// # Panics
    /// Does not panic.
    pub fn buffer_ring(&self, group: BufferGroupId) -> Result<&BufferRing> {
        self.resources
            .as_ref()
            .ok_or(UringError::InvalidConfig("resources are closed"))?
            .group(group)
    }

    /// Borrows the registered fixed-buffer pool.
    /// # Errors
    /// Returns an error if the pool is not configured or is closed.
    /// # Panics
    /// Does not panic.
    /// # Safety
    /// Derived handles must not outlive this ring; submit DMA tokens through its
    /// tracked buffer-preparation API or retain them through final completion.
    pub unsafe fn fixed_buffers(&self) -> Result<&FixedBufferPool> {
        self.resources
            .as_ref()
            .and_then(|resources| resources.buffers.as_ref())
            .ok_or(UringError::InvalidConfig(
                "fixed buffers are not configured",
            ))
    }
}
