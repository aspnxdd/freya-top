#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        generated::{bpf_get_smp_processor_id, bpf_ktime_get_ns},
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use freya_top_common::{EVENT_KIND_CPU_RUNTIME, EVENT_KIND_RUNQ_LATENCY, EVENT_KIND_WAKEUP, Event};

const SCHED_SWITCH_PREV_PID_OFFSET: usize = 24;
const SCHED_SWITCH_PREV_STATE_OFFSET: usize = 32;
const SCHED_SWITCH_NEXT_PID_OFFSET: usize = 56;
const SCHED_WAKEUP_PID_OFFSET: usize = 24;

const WAKE_SOURCE_WAKEUP: u32 = 1;
const WAKE_SOURCE_PREEMPTED: u32 = 2;

#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[repr(C)]
pub struct WakeupInfo {
    pub ts_ns: u64,
    pub source: u32,
}

#[repr(C)]
pub struct RunqInfo {
    pub latency_ns: u64,
    pub source: u32,
}

#[map]
static WAKEUPS: HashMap<u32, WakeupInfo> = HashMap::with_max_entries(8192, 0);

#[map]
static RUNNING: HashMap<u32, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static PENDING_RUNQ: HashMap<u32, RunqInfo> = HashMap::with_max_entries(8192, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    match try_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn emit_event(kind: u8, tid: u32, ts_ns: u64, value_ns: u64) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return Ok(());
    };
    unsafe {
        (*entry.as_mut_ptr()).kind = kind;
        (*entry.as_mut_ptr()).tid = tid;
        (*entry.as_mut_ptr()).cpu = bpf_get_smp_processor_id();
        (*entry.as_mut_ptr()).ts_ns = ts_ns;
        (*entry.as_mut_ptr()).value_ns = value_ns;

        entry.submit(0);
    }

    Ok(())
}
/**
*  CPU %       = how much CPU time the process consumed
   Wakeups/s   = how often it was woken from blocked/sleeping state
   Runq p95    = how long it waited runnable before getting CPU includes wakeups and preemptions
*/
fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    let prev_tid: u32 = unsafe { ctx.read_at::<i32>(SCHED_SWITCH_PREV_PID_OFFSET)? as u32 };
    let prev_state: i64 = unsafe { ctx.read_at::<i64>(SCHED_SWITCH_PREV_STATE_OFFSET)? };
    let next_tid: u32 = unsafe { ctx.read_at::<i32>(SCHED_SWITCH_NEXT_PID_OFFSET)? as u32 };

    let prev_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let prev_is_target = match TARGET_TGID.get(0) {
        Some(target) => target == &prev_tgid,
        None => false,
    };

    if prev_is_target {
        if let Some(start_ns) = unsafe { RUNNING.get(&prev_tid) } {
            emit_event(EVENT_KIND_CPU_RUNTIME, prev_tid, now, now - start_ns)?;
        }

        if let Some(runq) = unsafe { PENDING_RUNQ.get(&prev_tid) } {
            if runq.source == WAKE_SOURCE_WAKEUP {
                emit_event(EVENT_KIND_WAKEUP, prev_tid, now, 1)?;
            }
            emit_event(EVENT_KIND_RUNQ_LATENCY, prev_tid, now, runq.latency_ns)?;
        }

        if prev_state == 0 {
            let wakeup = WakeupInfo {
                ts_ns: now,
                source: WAKE_SOURCE_PREEMPTED,
            };
            let _ = WAKEUPS.insert(&prev_tid, &wakeup, 0);
        }
    }

    let _ = RUNNING.remove(&prev_tid);
    let _ = PENDING_RUNQ.remove(&prev_tid);

    if let Some(wakeup) = unsafe { WAKEUPS.get(&next_tid) } {
        let runq = RunqInfo {
            latency_ns: now - wakeup.ts_ns,
            source: wakeup.source,
        };
        let _ = PENDING_RUNQ.insert(&next_tid, &runq, 0);
    }

    let _ = WAKEUPS.remove(&next_tid);

    let _ = RUNNING.insert(&next_tid, &now, 0);

    Ok(0)
}

fn try_sched_wakeup(ctx: TracePointContext) -> Result<u32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };
    let tid: u32 = unsafe { ctx.read_at::<i32>(SCHED_WAKEUP_PID_OFFSET)? as u32 };
    let wakeup = WakeupInfo {
        ts_ns: now,
        source: WAKE_SOURCE_WAKEUP,
    };

    let _ = WAKEUPS.insert(&tid, &wakeup, 0);

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
