//! Bring the loopback interface up inside the fresh network namespace.
//!
//! A new netns has `lo` present but DOWN, so anything that binds or connects
//! to 127.0.0.1 (test servers, language servers, local registries in tests)
//! fails with ENETUNREACH. We send a single RTM_NEWLINK with IFF_UP over a
//! NETLINK_ROUTE socket — no external binaries, no `ip` dependency. Permitted
//! because we are root inside the user namespace that owns the netns.

use std::mem::size_of;

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
struct IfInfoMsg {
    family: u8,
    _pad: u8,
    ty: u16,
    index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
struct Req {
    hdr: NlMsgHdr,
    ifi: IfInfoMsg,
}

const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const LO_IFINDEX: i32 = 1;

pub fn loopback_up() -> anyhow::Result<()> {
    // SAFETY: plain libc socket calls with correctly sized, repr(C) buffers.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "netlink socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        let req = Req {
            hdr: NlMsgHdr {
                len: size_of::<Req>() as u32,
                ty: RTM_NEWLINK,
                flags: NLM_F_REQUEST | NLM_F_ACK,
                seq: 1,
                pid: 0,
            },
            ifi: IfInfoMsg {
                family: libc::AF_UNSPEC as u8,
                _pad: 0,
                ty: 0,
                index: LO_IFINDEX,
                flags: libc::IFF_UP as u32,
                change: libc::IFF_UP as u32,
            },
        };
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        let sent = libc::sendto(
            fd,
            &req as *const Req as *const libc::c_void,
            size_of::<Req>(),
            0,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        );
        if sent < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(anyhow::anyhow!("netlink sendto: {e}"));
        }
        // Read the ACK (an NLMSG_ERROR with error == 0).
        let mut buf = [0u8; 256];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
        libc::close(fd);
        if n < (size_of::<NlMsgHdr>() + 4) as isize {
            return Err(anyhow::anyhow!("netlink: short ack ({n} bytes)"));
        }
        // read_unaligned: `buf` is a `[u8; 256]` (align 1), so a plain reference-deref of a
        // multi-byte-field struct out of it would be UB on strict-alignment targets.
        let hdr = std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr);
        if hdr.ty == NLMSG_ERROR {
            let err = i32::from_ne_bytes([
                buf[size_of::<NlMsgHdr>()],
                buf[size_of::<NlMsgHdr>() + 1],
                buf[size_of::<NlMsgHdr>() + 2],
                buf[size_of::<NlMsgHdr>() + 3],
            ]);
            if err != 0 {
                return Err(anyhow::anyhow!(
                    "netlink RTM_NEWLINK(lo, IFF_UP) failed: {}",
                    std::io::Error::from_raw_os_error(-err)
                ));
            }
        }
    }
    Ok(())
}
