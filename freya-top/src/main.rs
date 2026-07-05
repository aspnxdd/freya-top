use std::{
    mem,
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::{Array, RingBuf},
    programs::TracePoint,
};
use freya_top_common::{
    EVENT_KIND_CPU_RUNTIME, EVENT_KIND_INVOLUNTARY_CONTEXT_SWITCH, EVENT_KIND_OFF_CPU_RUNTIME,
    EVENT_KIND_RUNQ_LATENCY, EVENT_KIND_VOLUNTARY_CONTEXT_SWITCH, EVENT_KIND_WAKEUP, Event,
};
#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use tokio::{signal, time};

fn set_target_pid(bpf: &mut Ebpf, pid: u32) -> anyhow::Result<()> {
    let mut target_tgid = Array::<_, u32>::try_from(bpf.map_mut("TARGET_TGID").unwrap())?;

    target_tgid.set(0, pid, 0)?;

    Ok(())
}

fn load(data: &[u8]) -> Event {
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
    event
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// PID of the process to trace
    #[arg(short, long)]
    pid: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

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

    let pid = args.pid;

    set_target_pid(&mut ebpf, pid)?;

    let program: &mut TracePoint = ebpf
        .program_mut("sched_switch")
        .ok_or_else(|| anyhow::anyhow!("sched_switch program not found"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

    let program: &mut TracePoint = ebpf
        .program_mut("sched_wakeup")
        .ok_or_else(|| anyhow::anyhow!("sched_wakeup program not found"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_wakeup")?;

    let mut ring_buf = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
    )?;

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let cores = std::thread::available_parallelism().map(|n| n.get())?;

    let mut window_start = Instant::now();
    let mut cpu_runtime_ns = 0u64;
    let mut wakeups = 0u64;
    let mut runq_latencies_ns = Vec::new();
    let mut voluntary_switches = 0u64;
    let mut involuntary_switches = 0u64;
    let mut off_cpu_latencies_ns = Vec::new();

    println!("Tracing scheduler events for PID {pid}. Press Ctrl-C to exit.");
    loop {
        tokio::select! {
            result = &mut ctrl_c => {
                result?;
                break;
            }
            _ = time::sleep(Duration::from_millis(50)) => {
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = &item;

                    if data.len() != mem::size_of::<Event>() {
                        eprintln!("unexpected event size: {}", data.len());
                        continue;
                    }

                    let event = load(data);
                    match event.kind {
                        EVENT_KIND_CPU_RUNTIME => {
                            cpu_runtime_ns = cpu_runtime_ns.saturating_add(event.value_ns)
                        }
                        EVENT_KIND_WAKEUP => wakeups += 1,
                        EVENT_KIND_RUNQ_LATENCY => {
                            runq_latencies_ns.push(event.value_ns);
                        }
                        EVENT_KIND_VOLUNTARY_CONTEXT_SWITCH => voluntary_switches += 1,
                        EVENT_KIND_INVOLUNTARY_CONTEXT_SWITCH => involuntary_switches += 1,
                        EVENT_KIND_OFF_CPU_RUNTIME => {
                            off_cpu_latencies_ns.push(event.value_ns);
                        },
                        _ =>println!("unknown event kind: {}", event.kind),
                    }
                }

                let elapsed = window_start.elapsed();
                if elapsed >= Duration::from_secs(1) {
                    let cpu_percentage = (cpu_runtime_ns as f64 / elapsed.as_nanos() as f64) * 100.0;
                    let wakeups_per_sec = wakeups as f64 / elapsed.as_secs_f64();
                    let runq_p95 = if runq_latencies_ns.is_empty() {
                        "n/a".to_string()
                    } else {
                        runq_latencies_ns.sort();
                        let index = ((runq_latencies_ns.len() - 1) as f64 * 0.95).ceil() as usize;
                        format!("{:.1}us", runq_latencies_ns[index] as f64 / 1_000.0)
                    };
                    let off_cpu_p95 = if off_cpu_latencies_ns.is_empty() {
                        "n/a".to_string()
                    } else {
                        off_cpu_latencies_ns.sort();
                        let index = ((off_cpu_latencies_ns.len() - 1) as f64 * 0.95).ceil() as usize;
                        format!("{:.1}us", off_cpu_latencies_ns[index] as f64 / 1_000.0)
                    };
                    let voluntary_switches_per_sec = voluntary_switches as f64 / elapsed.as_secs_f64();
                    let involuntary_switches_per_sec = involuntary_switches as f64 / elapsed.as_secs_f64();
                    println!(
                        "Thread CPU {:.6}%   Total CPU {:.6}%   Wakeups {:.0}/s   Run queue latency p95 {}   Voluntary context switches {:.0}/s   Involuntary context switches {:.0}/s   Off-CPU p95 {}",
                        cpu_percentage, cpu_percentage / cores as f64, wakeups_per_sec, runq_p95, voluntary_switches_per_sec, involuntary_switches_per_sec, off_cpu_p95
                    );

                    window_start = Instant::now();
                    cpu_runtime_ns = 0;
                    wakeups = 0;
                    runq_latencies_ns.clear();
                    voluntary_switches = 0;
                    involuntary_switches = 0;
                    off_cpu_latencies_ns.clear();
                }
            }
        }
    }

    println!("Exiting...");

    Ok(())
}
