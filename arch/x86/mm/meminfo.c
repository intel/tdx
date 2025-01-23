#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/set_memory.h>
#include <asm/tdx.h>

void arch_report_meminfo(struct seq_file *m)
{
	direct_pages_meminfo(m);
	tdx_meminfo(m);
}
