//! Compile-time packing for 56-bit operation payloads and subsystem ids.
//!
//! [`OpPayloadCodec`] packs a struct or enum into the low 56 bits of a `u64`.
//! [`define_subsystems`] declares a fieldless subsystem enum whose discriminants
//! are unique ids in `1..=255`. Id `0` is reserved for the proactor waker and
//! timer. This crate does not depend on `liburing` and does not generate
//! `SubsystemHandler` implementations.

#![deny(missing_docs)]

use proc_macro::TokenStream;

mod payload;
mod subsystems;

/// Pack a struct or enum into the low 56 bits of an operation payload.
///
/// The derive emits inherent `PAYLOAD_BITS`, `encode_payload`, and
/// `decode_payload`. Encoded values are at most `0x00FF_FFFF_FFFF_FFFF`.
/// Struct fields pack from the least significant bit in source order. `u8`
/// occupies 8 bits, `u16` occupies 16, and `u32` occupies 32. Fieldless enums
/// store their integer discriminant. Enums that carry fields use a dense tag
/// in the low bits, then that variant's fields.
/// Fields accept unqualified primitive names or paths through
/// `core::primitive` and `std::primitive`. The resolved type must match the
/// corresponding unsigned primitive; a shadowing alias to a wider or signed
/// type is rejected.
///
/// ```
/// use liburing_macros::OpPayloadCodec;
///
/// #[derive(OpPayloadCodec, Debug, PartialEq, Eq)]
/// struct Header {
///     kind: u8,
///     flags: u16,
///     len: u32,
/// }
///
/// let max = Header {
///     kind: 0xff,
///     flags: 0xffff,
///     len: 0xffff_ffff,
/// };
/// assert_eq!(max.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
/// assert_eq!(Header::decode_payload(max.encode_payload()), Ok(max));
/// ```
///
/// ```compile_fail
/// use liburing_macros::OpPayloadCodec;
///
/// #[derive(OpPayloadCodec)]
/// struct TooWide {
///     hi: u32,
///     lo: u32,
/// }
/// ```
///
/// A variant tag counts toward the 56-bit limit.
///
/// ```compile_fail
/// use liburing_macros::OpPayloadCodec;
///
/// #[derive(OpPayloadCodec)]
/// enum TooWideWithTag {
///     Empty,
///     Fields { raw: u8, body: u16, tag: u32 },
/// }
/// ```
///
/// Primitive-looking aliases cannot supply a different field width.
///
/// ```compile_fail
/// use liburing_macros::OpPayloadCodec;
///
/// #[allow(non_camel_case_types)]
/// type u8 = u64;
///
/// #[derive(OpPayloadCodec)]
/// struct WiderAlias { value: u8 }
/// ```
///
/// ```compile_fail
/// use liburing_macros::OpPayloadCodec;
///
/// #[allow(non_camel_case_types)]
/// mod protocol {
///     pub type u8 = u64;
/// }
///
/// #[derive(OpPayloadCodec)]
/// struct QualifiedAlias { value: protocol::u8 }
/// ```
///
/// Signed aliases are rejected even when their storage size matches.
///
/// ```compile_fail
/// use liburing_macros::OpPayloadCodec;
///
/// #[allow(non_camel_case_types)]
/// type u8 = i8;
///
/// #[derive(OpPayloadCodec)]
/// struct SignedAlias { value: u8 }
/// ```
///
/// # Errors
///
/// Expansion fails when the input is not a struct or enum, when the type has
/// generics, when a field does not name and resolve to `u8`, `u16`, or `u32`
/// through one of the accepted paths, when a fieldless
/// discriminant is negative, non-literal, or wider than 56 bits, or when the
/// packed width exceeds 56 bits.
///
/// # Panics
///
/// Expansion does not panic. Generated `encode_payload` and `decode_payload`
/// do not panic.
#[proc_macro_derive(OpPayloadCodec)]
pub fn derive_op_payload_codec(input: TokenStream) -> TokenStream {
    render(payload::expand(input.into()))
}

/// Declare subsystem ids in `1..=255`.
///
/// The macro emits `id`, `from_id`, `ALL`, `register_all`, `From<Self> for u8`,
/// and `TryFrom<u8>`. Discriminants must be unique integer literals. Zero is
/// rejected because the proactor reserves it for its waker and timer. Variant
/// names `ALL`, `id`, `from_id`, `register_all`, and `try_from` are reserved
/// for the generated routing API, including their raw identifier spellings.
/// `cfg` and `cfg_attr` attributes on the enum or its variants are rejected.
/// Apply conditional compilation to the entire macro invocation instead.
///
/// ```
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     pub enum DemoSubsystems {
///         Dns = 1,
///         Http = 2,
///     }
/// }
///
/// assert_eq!(DemoSubsystems::Http.id(), 2);
/// assert_eq!(DemoSubsystems::from_id(0), None);
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum Reserved {
///         Internal = 0,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum Duplicated {
///         Dns = 1,
///         Http = 1,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum Overflow {
///         Dns = 256,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     #[cfg(any())]
///     enum ConditionalEnum { Dns = 1 }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum ConditionalVariant {
///         Always = 1,
///         #[cfg(any())]
///         Disabled = 2,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     #[cfg_attr(all(), doc = "Conditional attributes are unsupported.")]
///     enum ConditionalEnumAttribute { Dns = 1 }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum ConditionalVariantAttribute {
///         #[cfg_attr(all(), doc = "Conditional attributes are unsupported.")]
///         Dns = 1,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum HiddenRoutingTable { ALL = 1 }
/// }
/// ```
///
/// ```compile_fail
/// use liburing_macros::define_subsystems;
///
/// define_subsystems! {
///     enum HiddenConversion { r#from_id = 1 }
/// }
/// ```
///
/// # Errors
///
/// Expansion fails when the input is not a fieldless enum, when a discriminant
/// is missing or not an integer literal, when an id is `0` or greater than
/// 255, when two variants share an id, or when the caller supplies `derive` or
/// `repr` attributes, or `cfg`/`cfg_attr` attributes on the enum or its variants.
/// Variant names reserved for the generated routing API are also rejected.
///
/// # Panics
///
/// Expansion does not panic. Generated `id` and `from_id` do not panic.
/// `register_all` panics only if its callback panics.
#[proc_macro]
pub fn define_subsystems(input: TokenStream) -> TokenStream {
    render(subsystems::expand(input.into()))
}

fn render(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    match result {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
