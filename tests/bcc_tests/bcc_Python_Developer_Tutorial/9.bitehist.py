#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF
from time import sleep

prog = '''
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
    dist.increment(bpf_log2l(req->__data_len / 1024));
    return 0;
}
'''
b = BPF(text=prog)

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
b["dist"].print_log2_hist("kbytes")