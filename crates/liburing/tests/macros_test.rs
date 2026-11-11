use liburing::{OperationPayloadCodec, define_subsystems};

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct Header {
    kind: u8,
    flags: u16,
    len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct Kind(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct Marker;

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct NamedFields {
    raw: u8,
    body: u16,
    tag: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct InternalNames {
    __uring_payload_raw: u8,
    __uring_payload_body: u8,
    __uring_payload_tag: u8,
    __uring_payload_field_0: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
enum NamedVariants {
    Empty,
    Fields {
        raw: u8,
        body: u16,
        tag: u16,
    },
    Internal {
        __uring_payload_raw: u8,
        __uring_payload_body: u8,
        __uring_payload_tag: u8,
        __uring_payload_field_0: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
enum SingleWideVariant {
    Fields { raw: u8, body: u16, tag: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
struct QualifiedPrimitives {
    raw: core::primitive::u8,
    body: std::primitive::u16,
    tag: ::core::primitive::u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
enum Opcode {
    Read = 1,
    Write = 2,
    Sync = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
#[repr(u64)]
enum MaxDisc {
    Limit = 0x00FF_FFFF_FFFF_FFFF,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
enum Msg {
    Ping,
    Len(u16),
    Body { tag: u8, len: u32 },
}

define_subsystems! {
    pub enum MySubsystems {
        Dns = 1,
        Http = 2,
        Wal = 3,
    }
}

#[test]
fn struct_roundtrip_covers_56bit_boundary() {
    assert_eq!(Header::PAYLOAD_BITS, 56);
    let sample = Header {
        kind: 0xAB,
        flags: 0xCDEF,
        len: 0x0123_4567,
    };
    let expected = 0xAB_u64 | (0xCDEF_u64 << 8) | (0x0123_4567_u64 << 24);
    assert_eq!(sample.encode_payload(), expected);
    assert_eq!(sample.encode_payload() >> 56, 0);
    assert_eq!(Header::decode_payload(expected), Ok(sample));

    let max = Header {
        kind: 0xFF,
        flags: 0xFFFF,
        len: 0xFFFF_FFFF,
    };
    assert_eq!(max.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
    assert_eq!(Header::decode_payload(0x00FF_FFFF_FFFF_FFFF), Ok(max));

    let overflow = 0x00FF_FFFF_FFFF_FFFF + 1;
    assert_eq!(Header::decode_payload(overflow), Err(overflow));
    assert_eq!(Header::decode_payload(u64::MAX), Err(u64::MAX));
}

#[test]
fn named_fields_preserve_56_payload_bits() {
    let value = NamedFields {
        raw: 0xA5,
        body: 0x1234,
        tag: 0x5678_9ABC,
    };
    assert_eq!(NamedFields::PAYLOAD_BITS, 56);
    let encoded = 0x0056_789A_BC12_34A5;
    assert_eq!(value.encode_payload(), encoded);
    assert_eq!(NamedFields::decode_payload(encoded), Ok(value));
    let max = NamedFields {
        raw: u8::MAX,
        body: u16::MAX,
        tag: u32::MAX,
    };
    assert_eq!(max.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
    assert_eq!(NamedFields::decode_payload(max.encode_payload()), Ok(max));
    assert_eq!(NamedFields::decode_payload(1_u64 << 56), Err(1_u64 << 56));
}

#[test]
fn internal_names_preserve_source_values() {
    let value = InternalNames {
        __uring_payload_raw: 0x12,
        __uring_payload_body: 0x34,
        __uring_payload_tag: 0x56,
        __uring_payload_field_0: 0x78,
    };
    assert_eq!(value.encode_payload(), 0x7856_3412);
    assert_eq!(InternalNames::decode_payload(0x7856_3412), Ok(value));
}

#[test]
fn named_variants_preserve_fields_and_tags() {
    let value = NamedVariants::Fields {
        raw: 0xAB,
        body: 0xCDEF,
        tag: 0x1234,
    };
    assert_eq!(NamedVariants::PAYLOAD_BITS, 42);
    let encoded = 1_u64 | (0xAB_u64 << 2) | (0xCDEF_u64 << 10) | (0x1234_u64 << 26);
    assert_eq!(value.encode_payload(), encoded);
    assert_eq!(NamedVariants::decode_payload(encoded), Ok(value));
    let internal = NamedVariants::Internal {
        __uring_payload_raw: 0x12,
        __uring_payload_body: 0x34,
        __uring_payload_tag: 0x56,
        __uring_payload_field_0: 0x78,
    };
    let internal_encoded = 2_u64 | (0x7856_3412_u64 << 2);
    assert_eq!(internal.encode_payload(), internal_encoded);
    assert_eq!(
        NamedVariants::decode_payload(internal_encoded),
        Ok(internal)
    );
    assert_eq!(NamedVariants::decode_payload(0), Ok(NamedVariants::Empty));
    assert_eq!(NamedVariants::decode_payload(3), Err(3));
    assert_eq!(NamedVariants::decode_payload(4), Err(4));
    let stray = internal_encoded | (1_u64 << 34);
    assert_eq!(NamedVariants::decode_payload(stray), Err(stray));
}

#[test]
fn single_variant_uses_56_bits() {
    let value = SingleWideVariant::Fields {
        raw: u8::MAX,
        body: u16::MAX,
        tag: u32::MAX,
    };
    assert_eq!(SingleWideVariant::PAYLOAD_BITS, 56);
    assert_eq!(value.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
    assert_eq!(
        SingleWideVariant::decode_payload(value.encode_payload()),
        Ok(value)
    );
    assert_eq!(
        SingleWideVariant::decode_payload(1_u64 << 56),
        Err(1_u64 << 56)
    );
}

#[test]
fn qualified_primitives_preserve_payload_layout() {
    let value = QualifiedPrimitives {
        raw: u8::MAX,
        body: u16::MAX,
        tag: u32::MAX,
    };
    assert_eq!(QualifiedPrimitives::PAYLOAD_BITS, 56);
    assert_eq!(value.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
    assert_eq!(
        QualifiedPrimitives::decode_payload(value.encode_payload()),
        Ok(value)
    );
}

#[test]
fn primitive_checks_ignore_caller_constants() {
    #[allow(non_upper_case_globals)]
    const value: u8 = 7;

    #[derive(Debug, PartialEq, Eq, OperationPayloadCodec)]
    struct Payload {
        raw: u8,
    }

    let expected = Payload { raw: value };
    assert_eq!(expected.encode_payload(), 7);
    assert_eq!(Payload::decode_payload(7), Ok(expected));
}

#[test]
fn narrow_payload_rejects_stray_bits() {
    assert_eq!(Kind::PAYLOAD_BITS, 8);
    assert_eq!(Kind(0xFF).encode_payload(), 0xFF);
    assert_eq!(Kind::decode_payload(0), Ok(Kind(0)));
    assert_eq!(Kind::decode_payload(0xFF), Ok(Kind(0xFF)));
    assert_eq!(Kind::decode_payload(0x100), Err(0x100));
    assert_eq!(Marker::PAYLOAD_BITS, 0);
    assert_eq!(Marker.encode_payload(), 0);
    assert_eq!(Marker::decode_payload(0), Ok(Marker));
    assert_eq!(Marker::decode_payload(1), Err(1));
}

#[test]
fn fieldless_enum_rejects_unknown_discriminant() {
    assert_eq!(Opcode::PAYLOAD_BITS, 3);
    assert_eq!(Opcode::Read.encode_payload(), 1);
    assert_eq!(Opcode::Write.encode_payload(), 2);
    assert_eq!(Opcode::Sync.encode_payload(), 7);
    assert_eq!(Opcode::decode_payload(1), Ok(Opcode::Read));
    assert_eq!(Opcode::decode_payload(7), Ok(Opcode::Sync));
    assert_eq!(Opcode::decode_payload(0), Err(0));
    assert_eq!(Opcode::decode_payload(3), Err(3));
    let high = 0x0100_0000_0000_0000;
    assert_eq!(Opcode::decode_payload(high), Err(high));
}

#[test]
fn max_discriminant_uses_all_56_bits() {
    assert_eq!(MaxDisc::PAYLOAD_BITS, 56);
    assert_eq!(MaxDisc::Limit.encode_payload(), 0x00FF_FFFF_FFFF_FFFF);
    assert_eq!(
        MaxDisc::decode_payload(0x00FF_FFFF_FFFF_FFFF),
        Ok(MaxDisc::Limit)
    );
    assert_eq!(MaxDisc::decode_payload(0), Err(0));
    let overflow = 0x00FF_FFFF_FFFF_FFFF + 1;
    assert_eq!(MaxDisc::decode_payload(overflow), Err(overflow));
}

#[test]
fn data_enum_packs_tag_then_fields() {
    assert_eq!(Msg::PAYLOAD_BITS, 42);
    assert_eq!(Msg::Ping.encode_payload(), 0);
    assert_eq!(Msg::decode_payload(0), Ok(Msg::Ping));

    let len = Msg::Len(0xABCD);
    let len_raw = 1_u64 | (0xABCD_u64 << 2);
    assert_eq!(len.encode_payload(), len_raw);
    assert_eq!(Msg::decode_payload(len_raw), Ok(len));

    let body = Msg::Body {
        tag: 0x7F,
        len: 0x0102_0304,
    };
    let body_raw = 2_u64 | (0x7F_u64 << 2) | (0x0102_0304_u64 << 10);
    assert_eq!(body.encode_payload(), body_raw);
    assert_eq!(Msg::decode_payload(body_raw), Ok(body));
    assert_eq!(body_raw >> 56, 0);

    assert_eq!(Msg::decode_payload(3), Err(3));
    assert_eq!(Msg::decode_payload(4), Err(4));
    let high = body_raw | (1_u64 << 56);
    assert_eq!(Msg::decode_payload(high), Err(high));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OperationPayloadCodec)]
enum Solo {
    Value(u8),
}

#[test]
fn single_variant_data_enum_roundtrip() {
    assert_eq!(Solo::PAYLOAD_BITS, 8);
    assert_eq!(Solo::Value(0x5A).encode_payload(), 0x5A);
    assert_eq!(Solo::decode_payload(0x5A), Ok(Solo::Value(0x5A)));
    assert_eq!(Solo::decode_payload(0x100), Err(0x100));
    let high = 1_u64 << 56;
    assert_eq!(Solo::decode_payload(high), Err(high));
}

#[test]
fn subsystem_ids_preserve_declaration_order() {
    const _: () = assert!(MySubsystems::Dns.id() == 1);
    const _: () = assert!(MySubsystems::Http.id() == 2);
    const _: () = assert!(MySubsystems::Wal.id() == 3);

    assert_eq!(MySubsystems::from_id(2), Some(MySubsystems::Http));
    assert_eq!(MySubsystems::from_id(0), None);
    assert_eq!(MySubsystems::from_id(9), None);
    assert_eq!(
        MySubsystems::ALL,
        &[MySubsystems::Dns, MySubsystems::Http, MySubsystems::Wal]
    );
    assert_eq!(u8::from(MySubsystems::Dns), 1);
    assert_eq!(MySubsystems::try_from(3_u8), Ok(MySubsystems::Wal));
    assert_eq!(MySubsystems::try_from(0_u8), Err(0));
    assert_eq!(MySubsystems::try_from(4_u8), Err(4));
}

mod subsystem_caller_hygiene {
    use super::define_subsystems;

    #[allow(non_camel_case_types)]
    type u8 = i8;
    #[allow(non_camel_case_types)]
    type u16 = i8;
    #[allow(non_camel_case_types)]
    type usize = i8;

    mod core {
        pub const CALL_SITE: () = ();
    }

    trait FnMut {}
    impl FnMut for () {}
    fn uses_local_trait<T: FnMut>(_: T) {}

    #[allow(non_upper_case_globals)]
    const register: u8 = 1;
    #[allow(non_upper_case_globals)]
    const id: u8 = 2;
    #[allow(non_upper_case_globals)]
    const value: u8 = 3;
    #[allow(non_upper_case_globals)]
    const error: u8 = 4;
    #[allow(non_upper_case_globals)]
    const widened: u8 = 5;
    #[allow(non_upper_case_globals)]
    const routing_id_in_range: u8 = 6;
    #[allow(non_upper_case_globals)]
    const __uring_subsystem_id: u8 = 7;
    #[allow(non_upper_case_globals)]
    const __uring_subsystem_register: u8 = 8;
    #[allow(non_upper_case_globals)]
    const __uring_subsystem_error: u8 = 9;
    #[allow(non_upper_case_globals)]
    const __uring_subsystem_value: u8 = 10;
    #[allow(non_upper_case_globals)]
    const __uring_subsystem_widened: u8 = 11;
    #[allow(non_upper_case_globals)]
    const __uring_dispatch_state: u8 = 12;
    #[allow(non_upper_case_globals)]
    const __uring_dispatch_callback: u8 = 13;
    #[allow(non_upper_case_globals)]
    const __uring_dispatch_completion: u8 = 14;
    #[allow(non_upper_case_globals)]
    const __uring_dispatch_context: u8 = 15;

    define_subsystems! {
        enum Routes { Low = 1, Wide = 200 }
    }

    #[test]
    fn subsystem_helpers_ignore_caller_bindings() {
        let _: u16 = 7;
        let _: usize = 8;
        let () = core::CALL_SITE;
        uses_local_trait(());
        assert_eq!(
            (register, id, value, error, widened, routing_id_in_range),
            (1, 2, 3, 4, 5, 6)
        );
        assert_eq!(
            (
                __uring_subsystem_id,
                __uring_subsystem_register,
                __uring_subsystem_error,
                __uring_subsystem_value,
                __uring_subsystem_widened,
            ),
            (7, 8, 9, 10, 11)
        );
        assert_eq!(
            (
                __uring_dispatch_state,
                __uring_dispatch_callback,
                __uring_dispatch_completion,
                __uring_dispatch_context
            ),
            (12, 13, 14, 15)
        );
        assert_eq!(Routes::Wide.id(), 200_u8);
        assert_eq!(Routes::from_id(200), Some(Routes::Wide));
        assert_eq!(Routes::from_id(0), None);
        assert_eq!(Routes::try_from(200_u8), Ok(Routes::Wide));
        assert_eq!(Routes::try_from(0_u8), Err(0_u8));
        assert_eq!(::core::primitive::u8::from(Routes::Wide), 200_u8);
        assert_eq!(Routes::ALL, &[Routes::Low, Routes::Wide]);
        let mut shared = Vec::<::core::primitive::u8>::new();
        let dispatcher = Routes::dispatcher(&mut shared, |route, state, _, _| {
            state.push(route.id());
            Ok(())
        });
        drop(dispatcher);
        assert!(shared.is_empty());
    }
}

#[test]
fn derived_payloads_satisfy_trait_contract() -> liburing::Result<()> {
    fn roundtrip<T: liburing::OperationPayloadCodec>(value: &T) -> liburing::Result<T> {
        T::decode_payload(value.encode_payload())
    }
    let header = Header {
        kind: 3,
        flags: 7,
        len: 11,
    };
    assert_eq!(roundtrip(&header)?, header);
    assert_eq!(
        roundtrip(&Msg::Body { tag: 5, len: 123 })?,
        Msg::Body { tag: 5, len: 123 }
    );
    assert_eq!(roundtrip(&Opcode::Sync)?, Opcode::Sync);
    assert_eq!(roundtrip(&Kind(255))?, Kind(255));
    assert_eq!(roundtrip(&Marker)?, Marker);
    let stray = liburing::OperationPayload::new_unchecked(1 << 8);
    assert_eq!(
        <Kind as liburing::OperationPayloadCodec>::decode_payload(stray),
        Err(liburing::UringError::InvalidPayload(1 << 8))
    );
    assert_eq!(
        <Opcode as liburing::OperationPayloadCodec>::decode_payload(
            liburing::OperationPayload::new_unchecked(3)
        ),
        Err(liburing::UringError::InvalidPayload(3))
    );
    const RAW: u64 = Kind(255).encode_payload();
    const DECODED: core::result::Result<Kind, u64> = Kind::decode_payload(RAW);
    assert_eq!(DECODED, Ok(Kind(255)));
    Ok(())
}

#[test]
fn dispatch_preserves_completion_fields() -> liburing::Result<()> {
    use liburing::{Completion, CompletionDispatcher, OperationId, OperationPayload, SubsystemId};

    let mut proactor = liburing::Proactor::builder().entries(8).build()?;
    let id = OperationId::pack(
        SubsystemId::new_unchecked(MySubsystems::Wal.id()),
        OperationPayload::new_unchecked(0x1234),
    );
    let mut seen = Vec::new();
    let mut dispatcher = MySubsystems::dispatcher(&mut seen, |route, state, completion, _| {
        assert_eq!(route, MySubsystems::Wal);
        assert_eq!(completion.operation_id, id);
        state.push((completion.result, completion.flags));
        Ok(())
    });
    fn accepts_static_dispatch<D: CompletionDispatcher>(_: &D) {}
    accepts_static_dispatch(&dispatcher);
    let mut callbacks = 0;
    proactor.alloc_sqe(id)?;
    proactor.wait_completions(
        1,
        Some(std::time::Duration::from_secs(3)),
        &mut |completion: Completion, ctx: &mut liburing::SubmissionContext<'_>| {
            callbacks += 1;
            dispatcher.dispatch(completion, ctx)?;
            for route in [0, 255] {
                let unknown = Completion {
                    operation_id: OperationId::pack(
                        SubsystemId::new_unchecked(route),
                        OperationPayload::new_unchecked(0x1234),
                    ),
                    result: 0,
                    flags: 0,
                };
                assert_eq!(
                    dispatcher.dispatch(unknown, ctx),
                    Err(liburing::UringError::InvalidSubsystemId(route))
                );
            }
            dispatcher.dispatch(
                Completion {
                    operation_id: id,
                    result: -22,
                    flags: 2,
                },
                ctx,
            )?;
            dispatcher.dispatch(
                Completion {
                    operation_id: id,
                    result: 17,
                    flags: 0x8000_0000,
                },
                ctx,
            )?;
            Ok(())
        },
    )?;
    drop(dispatcher);
    assert_eq!(callbacks, 1);
    assert_eq!(seen, [(0, 0), (-22, 2), (17, 0x8000_0000)]);
    Ok(())
}
