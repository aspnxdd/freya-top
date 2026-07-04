use std::{mem, thread, time::Duration};

use aya::{
    Ebpf,
    maps::{Array, RingBuf},
    programs::TracePoint,
};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

fn set_target_pid(bpf: &mut Ebpf, pid: u32) -> anyhow::Result<()> {
    let mut target_tgid = Array::<_, u32>::try_from(bpf.map_mut("TARGET_TGID").unwrap())?;

    target_tgid.set(0, pid, 0)?;

    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub kind: u32,
    pub tid: u32,
    pub cpu: u32,
    pub ts_ns: u64,
    pub value_ns: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/freya-top"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let pid = 487451;
    set_target_pid(&mut ebpf, pid)?;

    let program: &mut TracePoint = ebpf.program_mut("freya_top").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?)?;

    println!("Waiting for events...");
    loop {
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;

            if data.len() != mem::size_of::<Event>() {
                eprintln!("unexpected event size: {}", data.len());
                continue;
            }

            let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };

            println!(
                "kind={} tid={} cpu={} ts={} value_ns={}",
                event.kind, event.tid, event.cpu, event.ts_ns, event.value_ns,
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
