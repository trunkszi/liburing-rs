use liburing_macros::{OpPayloadCodec, define_subsystems};

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
struct Header {
    kind: u8,
    flags: u16,
    len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
struct Kind(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
struct Marker;

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
enum Opcode {
    Read = 1,
    Write = 2,
    Sync = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
#[repr(u64)]
enum MaxDisc {
    Limit = 0x00FF_FFFF_FFFF_FFFF,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, OpPayloadCodec)]
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
fn subsystem_ids_roundtrip_and_register_in_order() {
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

    let mut seen = Vec::new();
    let ok = MySubsystems::register_all(|subsystem| {
        seen.push(subsystem.id());
        Ok::<(), Stop>(())
    });
    assert_eq!(ok, Ok(()));
    assert_eq!(seen, vec![1, 2, 3]);

    let mut partial = Vec::new();
    let stopped = MySubsystems::register_all(|subsystem| {
        partial.push(subsystem.id());
        if subsystem.id() == 2 {
            Err(Stop)
        } else {
            Ok(())
        }
    });
    assert_eq!(stopped, Err(Stop));
    assert_eq!(partial, vec![1, 2]);
}

#[derive(Debug, PartialEq, Eq)]
struct Stop;
