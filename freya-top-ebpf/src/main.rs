#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[repr(C)]
pub struct WakeupInfo {
    pub ts_ns: u64,
}

#[repr(C)]
pub struct Event {
    pub kind: u32,
    pub tid: u32,
    pub cpu: u32,
    pub ts_ns: u64,
    pub value_ns: u64,
}

#[repr(u32)]
pub enum EventKind {
    RunqLatency = 1,
    CpuRuntime = 2,
}

#[map]
static WAKEUPS: HashMap<u32, WakeupInfo> = HashMap::with_max_entries(8192, 0);

#[map]
static RUNNING: HashMap<u32, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

fn is_target_process() -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();

    let tgid = (pid_tgid >> 32) as u32;

    match TARGET_TGID.get(0) {
        Some(target) => *target == tgid,
        None => false,
    }
}

#[tracepoint]
pub fn freya_top(ctx: TracePointContext) -> u32 {
    if !is_target_process() {
        return 0;
    }

    match try_freya_top(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn emit_event(kind: EventKind, tid: u32, ts_ns: u64, value_ns: u64) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return Ok(());
    };
    unsafe {
        (*entry.as_mut_ptr()).kind = kind as u32;
        (*entry.as_mut_ptr()).tid = tid;
        (*entry.as_mut_ptr()).cpu = 0;
        (*entry.as_mut_ptr()).ts_ns = ts_ns;
        (*entry.as_mut_ptr()).value_ns = value_ns;

        entry.submit(0);
    }

    Ok(())
}

fn try_freya_top(ctx: TracePointContext) -> Result<u32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    let prev_tid: u32 = unsafe { ctx.read_at::<i32>(24)? as u32 };
    let next_tid: u32 = unsafe { ctx.read_at::<i32>(56)? as u32 };

    if let Some(start_ns) = unsafe { RUNNING.get(&prev_tid) } {
        let runtime_ns = now - *start_ns;
        emit_event(EventKind::CpuRuntime, prev_tid, now, runtime_ns)?;
        RUNNING.remove(&prev_tid)?;
    }

    // Mark next thread as now running.
    RUNNING.insert(&next_tid, &now, 0)?;

    // Run queue latency: next thread woke up earlier and only now got CPU.
    if let Some(wakeup) = unsafe { WAKEUPS.get(&next_tid) } {
        let latency_ns = now - wakeup.ts_ns;
        emit_event(EventKind::RunqLatency, next_tid, now, latency_ns)?;
        WAKEUPS.remove(&next_tid)?;
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
