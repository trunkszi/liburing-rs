use std::{mem::ManuallyDrop, net::UdpSocket, os::fd::AsRawFd};

use liburing::{
    BufGroupId,
    pbuf_ring::{PbufLease, ProvidedBufRing},
};
use liburing_sys as sys;

use super::*;

fn stage_recv(
    proactor: &mut Proactor,
    fd: i32,
    id: OpId,
    group: BufGroupId,
) -> liburing::Result<()> {
    proactor.prepare_sqe_with(id, |sqe| {
        // SAFETY: The caller keeps the registered group alive through this
        // receive's final CQE; selected storage is accessed only via leases.
        unsafe { liburing::ops::net::prep_recv_multishot(sqe, fd, group, 0) };
    })
}

fn collect_depletion<'a>(
    proactor: &mut Proactor,
    buffers: &'a ProvidedBufRing,
    sockets: &[UdpSocket; 2],
    leases: &mut Vec<PbufLease<'a>>,
    next: &mut [u8; 2],
    expected_finals: usize,
) -> liburing::Result<usize> {
    let start = Instant::now();
    let mut finals = 0;
    let mut packets = 0;
    let mut ended = [false; 2];
    while finals < expected_finals {
        deadline(start);
        proactor.wait_completions(1, Some(WAIT), |completion, _| {
            let index = completion.op_id.payload().raw() as usize;
            assert!(index < 2);
            assert!(!ended[index], "CQE followed a terminal receive CQE");
            if completion.result == -libc::ENOBUFS {
                assert_eq!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                buffers.mark_depleted_recv(sockets[index].as_raw_fd(), 0, completion.op_id)?;
                ended[index] = true;
                finals += 1;
            } else {
                assert_eq!(completion.result, 2);
                assert_ne!(completion.flags & sys::IORING_CQE_F_MORE, 0);
                // SAFETY: This unconsumed successful CQE belongs to this exact
                // group; nonincremental selection transfers exclusive access.
                let lease = unsafe { buffers.lease_from_cqe(completion.flags, completion.result)? };
                assert_eq!(&lease[..], &[index as u8, next[index]]);
                next[index] += 1;
                packets += 1;
                leases.push(lease);
            }
            Ok(())
        })?;
    }
    Ok(packets)
}

#[test]
fn udp_burst_depletion_returns_one_credit_per_lease_without_rearm_herd() -> TestResult {
    let _serial = crate::kernel_test_lock();
    let receivers = [
        UdpSocket::bind("127.0.0.1:0")?,
        UdpSocket::bind("127.0.0.1:0")?,
    ];
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    for (index, receiver) in receivers.iter().enumerate() {
        receiver.set_nonblocking(true)?;
        for sequence in 0..32_u8 {
            assert_eq!(
                sender.send_to(&[index as u8, sequence], receiver.local_addr()?)?,
                2
            );
        }
    }
    let mut proactor = kernel(false)?;
    let records = Rc::new(RefCell::new(Vec::new()));
    proactor.register_subsystem(route(), Recorder(Rc::clone(&records)))?;
    // SAFETY: This owner exclusively registers group 19 on the live ring.
    // ManuallyDrop retains DMA storage on all error/unwind paths. Success drains
    // every final receive CQE before explicit unregistration and destruction.
    let mut buffers = ManuallyDrop::new(unsafe {
        ProvidedBufRing::new(proactor.ring_mut(), 2, 64, BufGroupId(19))?
    });
    let mut leases = Vec::new();
    let mut next = [0; 2];
    stage_recv(
        &mut proactor,
        receivers[0].as_raw_fd(),
        op(0),
        buffers.group_id(),
    )?;
    assert_eq!(
        collect_depletion(
            &mut proactor,
            &buffers,
            &receivers,
            &mut leases,
            &mut next,
            1
        )?,
        2
    );
    stage_recv(
        &mut proactor,
        receivers[1].as_raw_fd(),
        op(1),
        buffers.group_id(),
    )?;
    assert_eq!(
        collect_depletion(
            &mut proactor,
            &buffers,
            &receivers,
            &mut leases,
            &mut next,
            1
        )?,
        0
    );
    assert_eq!(leases.len(), 2);
    let mut total_rearms = 0;
    for _ in 0..8 {
        assert_eq!(
            buffers.rearm_depleted_recvs(|_, _, _, _| panic!("no lease was returned"))?,
            0
        );
        let returned_before = buffers.returned_count();
        for released in 1..=2 {
            drop(leases.pop().expect("exhausted group holds two leases"));
            assert_eq!(buffers.returned_count(), returned_before + released);
            let mut callbacks = 0;
            assert_eq!(
                buffers.rearm_depleted_recvs(|fd, flags, id, group| {
                    assert_eq!(flags, 0);
                    callbacks += 1;
                    stage_recv(&mut proactor, fd, id, group)
                })?,
                1,
                "one lease must rearm exactly one parked receive"
            );
            assert_eq!(callbacks, 1);
            assert_eq!(
                buffers.rearm_depleted_recvs(|_, _, _, _| panic!("credit reused"))?,
                0
            );
            total_rearms += callbacks;
        }
        // Neither rearm is submitted before both quota checks complete. There
        // are exactly two descriptors, so the burst must consume exactly two.
        assert_eq!(
            collect_depletion(
                &mut proactor,
                &buffers,
                &receivers,
                &mut leases,
                &mut next,
                2
            )?,
            2
        );
        assert_eq!(leases.len(), 2);
    }
    assert_eq!(total_rearms, 16);
    assert_eq!(usize::from(next[0]) + usize::from(next[1]), 18);
    assert!(buffers.forget_depleted_recv(op(0))?);
    assert!(buffers.forget_depleted_recv(op(1))?);
    drop(leases);
    assert_eq!(buffers.returned_count(), 18);
    assert_eq!(
        buffers.rearm_depleted_recvs(|_, _, _, _| panic!("forgotten receive"))?,
        0
    );
    // SAFETY: Both receives delivered terminal ENOBUFS CQEs in the last batch;
    // no leases or parked recovery records remain and the proactor is alive.
    unsafe {
        buffers.unregister()?;
        ManuallyDrop::drop(&mut buffers);
    }
    proactor.shutdown()?;
    Ok(())
}
