//! Diagnose whether this process can install ShitSpeak's eBPF TCP packet filter.
//!
//! Run this under the same systemd sandbox as `shitspeak-rs`. It intentionally
//! performs no packet collection: both file descriptors are closed on exit.

#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
const BPF_PROG_LOAD: u32 = 5;
#[cfg(target_os = "linux")]
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
#[cfg(target_os = "linux")]
const BPF_LD_ABS_H: u8 = 0x28;
#[cfg(target_os = "linux")]
const BPF_LD_ABS_B: u8 = 0x30;
#[cfg(target_os = "linux")]
const BPF_ALU64_MOV_K: u8 = 0xb7;
#[cfg(target_os = "linux")]
const BPF_ALU64_MOV_X: u8 = 0xbf;
#[cfg(target_os = "linux")]
const BPF_JMP_JEQ_K: u8 = 0x15;
#[cfg(target_os = "linux")]
const BPF_JMP_EXIT: u8 = 0x95;
#[cfg(target_os = "linux")]
const SO_ATTACH_BPF: libc::c_int = 50;
#[cfg(target_os = "linux")]
const VERIFIER_LOG_SIZE: usize = 64 * 1024;

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
}

#[cfg(target_os = "linux")]
fn main() {
    print_effective_capabilities();

    let packet_fd = match open_packet_socket() {
        Ok(fd) => {
            println!("AF_PACKET socket: available");
            fd
        }
        Err(error) => fail("AF_PACKET socket", error, None),
    };

    let program_fd = match load_socket_filter() {
        Ok(fd) => {
            println!("BPF_PROG_LOAD: available");
            fd
        }
        Err((error, verifier_log)) => fail("BPF_PROG_LOAD", error, verifier_log.as_deref()),
    };

    let result = unsafe {
        libc::setsockopt(
            packet_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_ATTACH_BPF,
            &program_fd.as_raw_fd() as *const RawFd as *const libc::c_void,
            mem::size_of::<RawFd>() as libc::socklen_t,
        )
    };
    if result != 0 {
        fail("SO_ATTACH_BPF", std::io::Error::last_os_error(), None);
    }
    println!("SO_ATTACH_BPF: available");
}

#[cfg(target_os = "linux")]
fn print_effective_capabilities() {
    let capability_line = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "CapEff: unavailable".to_owned());
    println!("{capability_line}");
}

#[cfg(target_os = "linux")]
fn open_packet_socket() -> std::io::Result<OwnedFd> {
    let protocol = u16::try_from(libc::ETH_P_ALL).unwrap_or_default().to_be() as libc::c_int;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn load_socket_filter() -> Result<OwnedFd, (std::io::Error, Option<String>)> {
    let instructions = socket_filter_instructions();
    let license = b"GPL\0";
    let mut verifier_log = vec![0u8; VERIFIER_LOG_SIZE];
    let attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: verifier_log.len() as u32,
        log_buf: verifier_log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: *b"ss_tcp_capture\0\0",
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &attr as *const BpfProgLoadAttr,
            mem::size_of::<BpfProgLoadAttr>(),
        ) as RawFd
    };
    if fd < 0 {
        let log = String::from_utf8_lossy(&verifier_log)
            .trim_matches(char::from(0))
            .trim()
            .to_owned();
        return Err((
            std::io::Error::last_os_error(),
            (!log.is_empty()).then_some(log),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn socket_filter_instructions() -> [BpfInsn; 19] {
    [
        BpfInsn {
            code: BPF_ALU64_MOV_X,
            dst_src: 0x16,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_LD_ABS_H,
            dst_src: 0,
            off: 0,
            imm: 12,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 6,
            imm: 0x0800,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 9,
            imm: 0x86dd,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 12,
            imm: 0x8100,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 11,
            imm: 0x88a8,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 10,
            imm: 0x9100,
        },
        BpfInsn {
            code: BPF_ALU64_MOV_K,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_JMP_EXIT,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_LD_ABS_B,
            dst_src: 0,
            off: 0,
            imm: 23,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 6,
            imm: libc::IPPROTO_TCP,
        },
        BpfInsn {
            code: BPF_ALU64_MOV_K,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_JMP_EXIT,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_LD_ABS_B,
            dst_src: 0,
            off: 0,
            imm: 20,
        },
        BpfInsn {
            code: BPF_JMP_JEQ_K,
            dst_src: 0,
            off: 2,
            imm: libc::IPPROTO_TCP,
        },
        BpfInsn {
            code: BPF_ALU64_MOV_K,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_JMP_EXIT,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: BPF_ALU64_MOV_K,
            dst_src: 0,
            off: 0,
            imm: -1,
        },
        BpfInsn {
            code: BPF_JMP_EXIT,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
    ]
}

#[cfg(target_os = "linux")]
fn fail(stage: &str, error: std::io::Error, verifier_log: Option<&str>) -> ! {
    eprintln!("{stage}: {error}");
    if let Some(verifier_log) = verifier_log {
        eprintln!("BPF verifier log:\n{verifier_log}");
    }
    std::process::exit(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-packet-capture-check requires Linux");
    std::process::exit(2);
}
