//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the whole operating system.
//!
//! A single global instance of [`Processor`] called `PROCESSOR` monitors running
//! task(s) for each core.
//!
//! A single global instance of `PID_ALLOCATOR` allocates pid for user apps.
//!
//! Be careful when you see `__switch` ASM function in `switch.S`. Control flow around this function
//! might not be what you expect.
mod context;
mod id;
mod manager;
mod processor;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use crate::config::{BIG_STRIDE, MAX_SYSCALL_NUM};
use crate::loader::get_app_data_by_name;
use crate::timer::get_time_us;
use alloc::sync::Arc;
use lazy_static::*;
pub use manager::{fetch_task, TaskManager};
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;
pub use id::{kstack_alloc, pid_alloc, KernelStack, PidHandle};
pub use manager::add_task;
pub use processor::{
    current_task, current_trap_cx, current_user_token, run_tasks, schedule, take_current_task,
    Processor,
};
/// Suspend the current 'Running' task and run the next task in task list.
pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    // change task stride
    task_inner.task_stride = task_inner.task_stride + BIG_STRIDE / task_inner.task_priority;
    drop(task_inner);
    // ---- release current PCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

/// pid of usertests app in make run TEST=1
pub const IDLE_PID: usize = 0;

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next(exit_code: i32) {
    // take from Processor
    let task = take_current_task().unwrap();

    let pid = task.getpid();
    if pid == IDLE_PID {
        println!(
            "[kernel] Idle process exit with exit_code {} ...",
            exit_code
        );
        panic!("All applications completed!");
    }

    // **** access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    // Change status to Zombie
    inner.task_status = TaskStatus::Zombie;
    // change task stride
    inner.task_stride = inner.task_stride + BIG_STRIDE / inner.task_priority;
    // Record exit code
    inner.exit_code = exit_code;
    // do not move to its parent but under initproc

    // ++++++ access initproc TCB exclusively
    {
        let mut initproc_inner = INITPROC.inner_exclusive_access();
        for child in inner.children.iter() {
            child.inner_exclusive_access().parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }
    // ++++++ release parent PCB

    inner.children.clear();
    // deallocate user space
    inner.memory_set.recycle_data_pages();
    drop(inner);
    // **** release current PCB
    // drop task manually to maintain rc correctly
    drop(task);
    // we do not have to save task context
    let mut _unused = TaskContext::zero_init();
    schedule(&mut _unused as *mut _);
}

lazy_static! {
    /// Creation of initial process
    ///
    /// the name "initproc" may be changed to any other app name like "usertests",
    /// but we have user_shell, so we don't need to change it.
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new(TaskControlBlock::new(
        get_app_data_by_name("ch5b_initproc").unwrap()
    ));
}

///Add init process to the manager
pub fn add_initproc() {
    add_task(INITPROC.clone());
}

/// increase_current_syscall_count
pub fn increase_current_syscall_count(syscall_id: usize) {
    if syscall_id >= MAX_SYSCALL_NUM {
        return;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    inner.syscall_times[syscall_id] += 1;
}

/// get_current_task_info
pub fn get_current_task_info() -> (TaskStatus, [u32; MAX_SYSCALL_NUM], usize) {
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    (
        inner.task_status,
        inner.syscall_times,
        get_time_us() / 1000 - inner.start_ms,
    )
}

/// memory alloc
pub fn memory_alloc(start: usize, len: usize, port: usize) -> isize {
    // println!("0x{:X} {}", start, len);
    if len == 0 {
        return 0;
    }
    if (len > 1073741824) || ((port & (!0x7)) != 0) || ((port & 0x7) == 0) || ((start % 4096) != 0)
    {
        return -1;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let mem_set = &mut inner.memory_set;

    if !mem_set.memory_alloc(start, len, port) {
        return -1;
    }

    0
}

/// memory free
pub fn memory_free(start: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    if start % 4096 != 0 {
        return -1;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let mem_set = &mut inner.memory_set;

    if !mem_set.memory_free(start, len) {
        return -1;
    }

    0
}
/// set_task_priority
pub fn set_task_priority(pri: usize) {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .task_priority = pri
}
