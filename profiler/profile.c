#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;                            // 用户空间下的PID
    u64 kernel_ip;                      
    int user_stack_id;                  // 用户栈ID
    int kernel_stack_id;                // 内核栈ID
    char name[TASK_COMM_LEN];           // 命令名
};
BPF_HASH(counts, struct key_t);         // 每个key_t => 次数，用于计数
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);          // 栈存储,使用栈ID索引

// This code gets a bit complex. Probably not suitable for casual hacking.

int do_perf_event(struct  bpf_perf_event_data*ctx) {
    // 分别获取pid和tgid
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;                // 高32位是线程组ID(在用户空间为PID)
    u32 pid = id;                       // 低32位是进程pid(在用户空间为线程id)

    // 用于替换判断某些功能是否开启
    if (IDLE_FILTER)
        return 0;

    if (!(THREAD_FILTER))
        return 0;

    if (container_should_be_filtered()) {
        return 0;
    }

    // create map key
    struct key_t key = {.pid = tgid};
    // 获取当前命令
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks/获得调用栈，USER_STACK_GET、KERNEL_STACK_GET都是要被替换的方法字符串
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;

    // 获取kernel_ip
    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        u64 ip = PT_REGS_IP(&ctx->regs);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking / 如果IP不健全，将key IP设为0以便以后检查
        // 根据不同内核版本设置page_offset
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif

        if (ip > page_offset) { 
            key.kernel_ip = ip;
        }
    }

    // 加入到map映射中
    counts.increment(key);  // 计数累加
    return 0;
}