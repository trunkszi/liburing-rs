//! Typed SQE and enter flags over the native UAPI constants.
use super::sys::{params::*, sqe::*};
macro_rules! flags {
    ($name:ident, $word:ty, {$($flag:ident = $value:expr),* $(,)?}) => {
        /// Native flag word; construction transfers no operand ownership.
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name($word);
        uarch::layout::assert_layout!($name, size = size_of::<$word>(), align = align_of::<$word>());
        impl $name {
            $(pub const $flag: Self = Self($value);)*
            /// Returns an empty mask.
            /// # Errors
            /// Does not return errors.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub const fn empty() -> Self { Self(0) }
            /// Returns the raw kernel flag word.
            /// # Errors
            /// Does not return errors.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub const fn bits(self) -> $word { self.0 }
            /// Tests whether no flags are set.
            /// # Errors
            /// Does not return errors.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub const fn is_empty(self) -> bool { self.0 == 0 }
            /// Tests inclusion of a flag mask.
            /// # Errors
            /// Does not return errors.
            /// # Panics
            /// Does not panic.
            #[uarch::prelude::hot_inline]
            pub const fn contains(self, flags: Self) -> bool { self.0 & flags.0 == flags.0 }
        }
        impl core::ops::BitOr for $name { type Output=Self; fn bitor(self,rhs:Self)->Self {Self(self.0|rhs.0)} }
        impl core::ops::BitOrAssign for $name { fn bitor_assign(&mut self,rhs:Self) {self.0|=rhs.0;} }
    }
}
flags!(Flags,u8, {
    FIXED_FILE=IOSQE_FIXED_FILE, IO_DRAIN=IOSQE_IO_DRAIN, IO_LINK=IOSQE_IO_LINK,
    IO_HARDLINK=IOSQE_IO_HARDLINK, ASYNC=IOSQE_ASYNC, BUFFER_SELECT=IOSQE_BUFFER_SELECT,
    SKIP_SUCCESS=IOSQE_CQE_SKIP_SUCCESS,
});
flags!(EnterFlags,u32, {
    GETEVENTS=IORING_ENTER_GETEVENTS, SQ_WAKEUP=IORING_ENTER_SQ_WAKEUP,
    EXT_ARG=IORING_ENTER_EXT_ARG, NO_IOWAIT=IORING_ENTER_NO_IOWAIT,
});
