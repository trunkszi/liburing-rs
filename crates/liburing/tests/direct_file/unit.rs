//! Direct-file alignment and backing-device identity boundaries.

use super::validate_transfer;
use crate::UringError;

#[test]
fn misaligned_address_rejected() {
    let rejected = validate_transfer(4096, 512, 4097, 512, 4096, 0);
    assert!(matches!(rejected, Err(UringError::InvalidConfig(_))));
    let accepted = validate_transfer(4096, 512, 8192, 512, 4096, 1024);
    assert!(accepted.is_ok());
}

#[test]
fn device_id_selects_block_or_filesystem() {
    // SAFETY: Linux stat contains plain integer fields; all-zero storage is valid.
    let mut stat = unsafe { std::mem::MaybeUninit::<libc::stat>::zeroed().assume_init() };
    stat.st_dev = libc::makedev(0, 7);
    stat.st_rdev = libc::makedev(259, 0);
    stat.st_mode = libc::S_IFBLK;
    assert_eq!(super::block_device_id(&stat), stat.st_rdev);
    stat.st_mode = libc::S_IFREG;
    assert_eq!(super::block_device_id(&stat), stat.st_dev);
}
