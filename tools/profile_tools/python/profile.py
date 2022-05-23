import argparse
from ast import arg
from cgi import test
import errno
from bcc.containers import filter_by_containers
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep
import signal

# 检查是否为正整数（包括0）
def positive_int(val):
    # 判断类型
    try:
        ival = int(val)
    except: argparse.ArgumentTypeError("must be a integer.")
    # 判断>0
    if ival < 0:
        raise argparse.ArgumentTypeError("must be a positive.")
    return ival
    
# 检查正整数（不包括0）
def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must not nonzero.")
    return ival

# 判断堆栈id是否正确，返回true代表出现错误
def stack_id_err(stack_id):
    # -EFAULT: 通常在get_stackid中表示无法获取内核堆栈追踪(stack-trace)（例如在用户态代码获取） 
    return (stack_id < 0) and (stack_id != -errno.EFAULT)           # TODO 为什么判断<0?

# 参数示例
examples = """examples:
    ./profile             # profile stack traces at 49 Hertz until Ctrl-C
    ./profile -F 99       # profile stack traces at 99 Hertz
    ./profile -c 1000000  # profile stack traces every 1 in a million events
    ./profile 5           # profile at 49 Hertz for 5 seconds only
    ./profile -f 5        # output in folded format for flame graphs
    ./profile -p 185      # only profile process with PID 185
    ./profile -L 185      # only profile thread with TID 185
    ./profile -U          # only show user space stacks (no kernel)
    ./profile -K          # only show kernel space stacks (no user)
    ./profile --cgroupmap mappath  # only trace cgroups in this BPF map
    ./profile --mntnsmap mappath   # only trace mount namespaces in the map
"""


parser = argparse.ArgumentParser(
    description="Profile CPU stack traces at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples
)

# 定义参数逻辑
# 线程组（互斥组表示只能设置其中一个）
thread_group = parser.add_mutually_exclusive_group()
thread_group.add_argument("-p", "--pid", type=positive_int, help="profile process with this PID only")   
thread_group.add_argument("-L", "--tid", type=positive_int, help="profile thread with this TID only")    
# TODO: add options for user/kernel threads only 

# 堆栈组
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true", help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true", help="show stacks from kernel space only (no user space stacks)")

# 采样组
sample_group = parser.add_mutually_exclusive_group()
sample_group.add_argument("-F", "--frequency", type=positive_int, help="sample frequency, Hertz")
sample_group.add_argument("-c", "--count", type=positive_int, help="sample period, number of events")

# 其他选项
parser.add_argument("-d", "--delimited", action="store_true", help="insert delimiter between kernel/user stacks")  
parser.add_argument("-a", "--annotations", action="store_true", help="add _[k] annotations to kernel frames")
parser.add_argument("-I", "--include-idle", action="store_true", help="include CPU idle stacks")
parser.add_argument("-f", "--folded", action="store_true", help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("--stack-storage-size", default=16384, type=positive_nonzero_int, 
    help="the number of unique stack traces that can be stored and "
        "displayed (default %(default)s)")
parser.add_argument("duration", nargs="?", default=99999999, type=positive_nonzero_int, help="duration of trace, in seconds")
parser.add_argument("-C", "--cpu", type=int, default=-1, help="cpu number to run profile on")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
parser.add_argument("--cgroupmap", help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap", help="trace mount namespaces in this BPF map only")

# 解析参数
args = parser.parse_args()
pid = int(args.pid) if args.pid is not None else -1
duration = int(args.duration())
debug = 0
need_delimiter = args.delimited and not (args.kernel_stacks_only or args.user_stacks_only)
# TODO: add stack depth, and interval

# bpf代码
bpf_text = '''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u64 kernel_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];           // 内核命令名
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

// This code gets a bit complex. Probably not suitable for casual hacking.

int do_perf_event(struct bpf_perf_event_data *ctx) {
    // 分别获取pid和tgid
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

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

    // get stacks
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;

    // 获取kernel_ip
    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        u64 ip = PT_REGS_IP(&ctx->regs);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
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
    counts.increment(key);
    return 0;
}
'''

#
# 对BPF程序做一些设置/替换源文件内容
#

# 设置CPU空闲栈过滤 TODO IDLE_FILTER的含义？
idle_filter = "pid == 0"
if args.include_idle:
    idle_filter = "0" 
bpf_text = bpf_text.replace('IDLE_FILTER', idle_filter)

# 设置进程/线程过滤
thread_context = ""
if args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = "tgid == %s" % args.pid     # TODO tgid、pid、tid
elif args.tid is not None:
    thread_context = "TID %s" % args.tid
    thread_filter = "pid == %s" % args.tid
else: 
    thread_context = "all threads"
    thread_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)

# 设置存储栈大小 TODO bpf程序的栈大小
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# 设置获取用户栈、内核栈id的方法
kernel_stack_get = "stack_traces.get_stackid(&ctx->regs, 0)"
user_stack_get = "stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)"
stack_context = ""
if args.user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"     # 设置-1保持互斥：让另一方不用获取
elif args.kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
else:
    stack_context = "user + kernel"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

# 设置容器相关过滤：cgroups、mountNS
bpf_text = filter_by_containers(args) + bpf_text        # filter_by_containers的作用就是给eBPF源代码字符串添加两个过滤函数(cgroups、mntns)

# 设置采样相关
sample_freq = 0
sample_period = 0
if args.frequency:
    sample_freq = args.frequency
elif args.count:
    sample_period = args.count
else:
    # If user didn't specify anything, use default 49Hz sampling
    sample_freq = 49
sample_context = "%s%d %s" % (("", sample_freq, "Hertz") if sample_freq else ("every ", sample_period, "events"))

#
# 输出头部
#

if not args.folded:
    # 不需要折叠输出(火焰图)
    print("Sampling at %s of %s by %s stack" %
        (sample_context, thread_context, stack_context), end="")
    if args.cpu >= 0:
        print(" on CPU#{}".format(args.cpu), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

if debug or args.ebpf:
    # 如果是debug模式或者指定了ebpf，则输出ebpf源代码
    print(bpf_text)
    if args.ebpf:
        exit()

#
# 初始化BPF
#

b = BPF(test=bpf_text)
# 埋点
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=sample_period, sample_freq=sample_freq, cpu=args.cpu)    # TODO ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK 怎么理解

# 处理信号
def signal_ignore(signal, frame):
    print()

#
# 输出报告（根据map）
#

# 收集采样
try:
    sleep(duration)
except KeyboardInterrupt:
    # as cleanup can take some time, trap Ctrl-C:  处理ctrl+C
    signal.signal(signal.SIGINT, signal_ignore)

if not args.folded:
    print()

def aksym(addr):
    if args.annotations:
        # ksym：将内核内存地址转换为内核函数名
        return b.ksym(addr) + "_[k]".encode()
    else:
        return b.ksym(addr)

# 输出
missing_stacks = 0  # 
has_collision = False
counts = b.get_table("counts")      # counts、stack_traces两个自定义map实例
stack_traces = b.get_table("stack_traces")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # 处理 get_stackid errors
    if not args.user_stacks_only and stack_id_err(k.kernel_stack_id):
        missing_stacks += 1
        # hash collision (-EEXIST) suggests that the map size may be too small
        has_collision = has_collision or k.kernel_stack_id == -errno.EEXIST
    if not args.kernel_stacks_only and stack_id_err(k.user_stack_id):
        missing_stacks += 1
        has_collision = has_collision or k.user_stack_id == -errno.EEXIST
    user_stack = [] if k.user_stack_id < 0 else stack_traces.walk(k.user_stack_id)
    kernel_tmp = [] if k.kernel_stack_id < 0 else stack_traces.walk(k.kernel_stack_id)
    