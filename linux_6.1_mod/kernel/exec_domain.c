// SPDX-License-Identifier: GPL-2.0
/*
 * Handling of different ABIs (personalities).
 *
 * We group personalities into execution domains which have their
 * own handlers for kernel entry points, signal mapping, etc...
 *
 * 2001-05-06	Complete rewrite,  Christoph Hellwig (hch@infradead.org)
 */

#include <net/sclda.h>

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/types.h>

#ifdef CONFIG_PROC_FS
static int execdomains_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "0-0\tLinux           \t[kernel]\n");
	return 0;
}

static int __init proc_execdomains_init(void)
{
	proc_create_single("execdomains", 0, NULL, execdomains_proc_show);
	return 0;
}
module_init(proc_execdomains_init);
#endif

SYSCALL_DEFINE1(personality, unsigned int, personality) {
    struct sclda_iov siov, path_iov;
    size_t written = 0;

    unsigned int retval = current->personality;
    if (personality != 0xffffffff) set_personality(personality);

    if (!is_sclda_allsend_fin()) return retval;

    siov.len = 100;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) return retval;
    written = snprintf(siov.str, siov.len, "135%c%u%c%u", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, personality);
    sclda_send_syscall_info(siov.str, written);
    return retval;
}
