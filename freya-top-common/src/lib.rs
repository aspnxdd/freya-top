#![no_std]

pub const EVENT_KIND_RUNQ_LATENCY: u8 = 1;
pub const EVENT_KIND_CPU_RUNTIME: u8 = 2;
pub const EVENT_KIND_WAKEUP: u8 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub ts_ns: u64,
    pub value_ns: u64,
    pub tid: u32,
    pub cpu: u32,
    pub kind: u8,
}
