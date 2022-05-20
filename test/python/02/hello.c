int hello_world(void *ctx) 
{
    bpf_trace_printk("Hello, World!\n");
    return 0;
}
