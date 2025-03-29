/*
 * Helper library for ftrace hooking kernel functions
 * Author: Harvey Phillips (xcellerator@gmx.com)
 * License: GPL
 *
 * Modificado para kernel 5.15:
 * - Se cambia la firma de la función callback para usar struct ftrace_regs.
 * - Se reemplaza FTRACE_OPS_FL_RECURSION_SAFE por FTRACE_OPS_FL_RECURSION.
 */

 #include <linux/ftrace.h>
 #include <linux/linkage.h>
 #include <linux/slab.h>
 #include <linux/uaccess.h>
 #include <linux/version.h>
 
 #if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
 #define PTREGS_SYSCALL_STUBS 1
 #endif
 
 /*
  * En kernels >= 5.7, kallsyms_lookup_name() no está exportado,
  * así que se usa kprobes para obtener su dirección.
  */
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
 #define KPROBE_LOOKUP 1
 #include <linux/kprobes.h>
 static struct kprobe kp = {
     .symbol_name = "kallsyms_lookup_name"
 };
 #endif
 
 #define HOOK(_name, _hook, _orig)   \
 {                   \
     .name = (_name),        \
     .function = (_hook),        \
     .original = (_orig),        \
 }
 
 /* Prevenir bucles recursivos al hookear */
 #define USE_FENTRY_OFFSET 0
 #if !USE_FENTRY_OFFSET
 #pragma GCC optimize("-fno-optimize-sibling-calls")
 #endif
 
 /* Estructura que almacena la información del hook */
 struct ftrace_hook {
     const char *name;
     void *function;
     void *original;
 
     unsigned long address;
     struct ftrace_ops ops;
 };
 
 /* Resuelve la dirección de la función original usando kallsyms_lookup_name */
 static int fh_resolve_hook_address(struct ftrace_hook *hook)
 {
 #ifdef KPROBE_LOOKUP
     typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
     kallsyms_lookup_name_t kallsyms_lookup_name;
     register_kprobe(&kp);
     kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
     unregister_kprobe(&kp);
 #endif
     hook->address = kallsyms_lookup_name(hook->name);
 
     if (!hook->address) {
         printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
         return -ENOENT;
     }
 
 #if USE_FENTRY_OFFSET
     *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
 #else
     *((unsigned long *)hook->original) = hook->address;
 #endif
 
     return 0;
 }
 
 /* Función callback modificada para usar struct ftrace_regs.
  * Se obtiene el puntero a pt_regs a partir de fregs mediante ftrace_get_regs().
  */
 static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops, struct ftrace_regs *fregs)
 {
     struct pt_regs *regs = ftrace_get_regs(fregs);
     struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
 
 #if USE_FENTRY_OFFSET
     regs->ip = (unsigned long)hook->function;
 #else
     if (!within_module(parent_ip, THIS_MODULE))
         regs->ip = (unsigned long)hook->function;
 #endif
 }
 
 /* Instala un hook en la función indicada.
  * Se configura la estructura ftrace_ops usando las banderas:
  * - FTRACE_OPS_FL_SAVE_REGS: para guardar los registros.
  * - FTRACE_OPS_FL_IPMODIFY: para permitir modificar el registro ip.
  * - FTRACE_OPS_FL_RECURSION: en reemplazo de la antigua FTRACE_OPS_FL_RECURSION_SAFE.
  */
 int fh_install_hook(struct ftrace_hook *hook)
 {
     int err;
     err = fh_resolve_hook_address(hook);
     if (err)
         return err;
 
     hook->ops.func = fh_ftrace_thunk;
     hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                       | FTRACE_OPS_FL_RECURSION
                       | FTRACE_OPS_FL_IPMODIFY;
 
     err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
     if (err) {
         printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
         return err;
     }
 
     err = register_ftrace_function(&hook->ops);
     if (err) {
         printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
         return err;
     }
 
     return 0;
 }
 
 /* Desinstala el hook */
 void fh_remove_hook(struct ftrace_hook *hook)
 {
     int err;
     err = unregister_ftrace_function(&hook->ops);
     if (err)
         printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
 
     err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
     if (err)
         printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
 }
 
 /* Instala múltiples hooks */
 int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
 {
     int err;
     size_t i;
 
     for (i = 0; i < count; i++) {
         err = fh_install_hook(&hooks[i]);
         if (err)
             goto error;
     }
     return 0;
 
 error:
     while (i != 0)
         fh_remove_hook(&hooks[--i]);
     return err;
 }
 
 /* Desinstala múltiples hooks */
 void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
 {
     size_t i;
     for (i = 0; i < count; i++)
         fh_remove_hook(&hooks[i]);
 }