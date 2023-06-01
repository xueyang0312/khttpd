from bcc import BPF
code = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u64);

int probe_handler(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	bpf_trace_printk("in %llu\\n",ts);
	return 0;
}

int end_function(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	bpf_trace_printk("out %llu\\n",ts);
	return 0;
}
"""

b = BPF(text = code)
b.attach_kprobe(event = 'my_kthread_run', fn_name = 'probe_handler')
b.attach_kretprobe(event = 'my_kthread_run', fn_name = 'end_function')

while True:
	try:
		res = b.trace_fields()
	except ValueError:
		continue
	print(res[5].decode("UTF-8"))