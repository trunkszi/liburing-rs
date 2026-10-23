use liburing_macros::{OperationPayloadCodec, define_subsystems};

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
fn unit_named_fields_preserve_all_56_payload_bits() {
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
fn unit_internal_name_fields_preserve_source_values() {
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
fn unit_named_variants_preserve_fields_and_dense_tag() {
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
fn unit_single_variant_uses_all_56_bits_without_tag() {
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
fn unit_qualified_primitive_paths_preserve_56bit_layout() {
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
fn unit_primitive_checks_do_not_capture_caller_constants() {
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
fn subsystem_ids_roundtrip_and_preserve_declaration_order() {
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
    fn unit_scenario_subsystem_helpers_ignore_caller_bindings() {
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
