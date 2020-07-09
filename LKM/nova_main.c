#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

// #include <linux/module.h>
#include <linux/kallsyms.h>
// #include <linux/kernel.h>
// #include <linux/init.h>
// #include <linux/syscalls.h>
// #include <linux/unistd.h>
// #include <linux/cred.h>
// #include <linux/fcntl.h>
// #include <linux/string.h>

#include "kern_version_adjustment.h"
#include "nova_syscall.h"

MODULE_LICENSE("GPL");

#define LKM_INTERFACE_FILE_PROC "hello"

#define CR0_WRITE_UNLOCK(x) \
    do { \
        unsigned long __cr0; \
        preempt_disable(); \
        __cr0 = read_cr0() & (~X86_CR0_WP); \
        BUG_ON(unlikely((__cr0 & X86_CR0_WP))); \
        write_cr0(__cr0); \
        x; \
        __cr0 = read_cr0() | X86_CR0_WP; \
        BUG_ON(unlikely(!(__cr0 & X86_CR0_WP))); \
        write_cr0(__cr0); \
        preempt_enable(); \
    } while (0)

inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}


static char redirectionConfigured = 0;

static void configureSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    void **sys_call_table;
    int i, numHandled;

    if(redirectionConfigured) return;
    redirectionConfigured = 1;

    numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);

    sys_call_table = (void *) kallsyms_lookup_name(sym_name);

    //TODO add a loop
    for(i = 0; i < numHandled; i++) {
        NOVA_STORE_ORIG(nova_handled_syscals[i], sys_call_table);
    }
//     printk(KERN_ALERT "orig open: %p\n", sys_call_table[__NR_open]);
//     NOVA_STORE_ORIG(__NR_open, sys_call_table);

//     write_cr0(read_cr0() & (~0x10000)); //remove write protection
//     disable_write_protection();

    CR0_WRITE_UNLOCK({
    //TODO add another loop
        for(i = 0; i < numHandled; i++) {
            NOVA_REDIRECT(nova_handled_syscals[i], sys_call_table);
        }
//     NOVA_REDIRECT(__NR_open, sys_call_table);
    });
//     enable_write_protection();
    printk(KERN_ALERT "tainted open: %p\n", sys_call_table[__NR_open]);
    printk(KERN_ALERT "tainted syscall added\n");
//     write_cr0(read_cr0() | 0x10000); //restore write protection
}

static void restorSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    void **sys_call_table;
    int i, numHandled;

    if(!redirectionConfigured) return;
    redirectionConfigured = 0;

    numHandled = sizeof(nova_handled_syscals)/sizeof(nova_handled_syscals[0]);

    sys_call_table = (void **) kallsyms_lookup_name(sym_name);

//     write_cr0(read_cr0() & (~0x10000)); //remove write protection
//     disable_write_protection();
    CR0_WRITE_UNLOCK({

    //TODO add another loop
        for(i = 0; i < numHandled; i++) {
            NOVA_RESTORE(nova_handled_syscals[i], sys_call_table);
        }
//     NOVA_RESTORE(__NR_open, sys_call_table);
    });

    printk(KERN_ALERT "tainted syscall removed\n");
}

static ssize_t write(struct file *file, const char *buf, size_t count, loff_t *pos) {
    if(!buf || !count) return -EINVAL;
    if(buf[0]) configureSyscallRedirection();
    else restorSyscallRedirection();
    return 1;

}

static ssize_t read(struct file *file, char *buf, size_t count, loff_t *pos) {
    int ret = 0;
    char buffer[32];
    if(!buf || !count) return -EINVAL;
    if(count < 20 || *pos < 0) return -EINVAL;
    if(*pos >= 20) return 0;

    ret = snprintf(buffer, 32, "%ld %ld\n", functionRedirected, activeRedirection);

    if (count < ret)
        ret = count;

    if(*pos >= ret) return 0;

    if(copy_to_user(buf, buffer + (*pos), ret)) return -ENOBUFS;

    *pos += ret;

    return ret;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
static struct file_operations file_ops;
static struct proc_dir_entry *init_procfile(void) {
    struct proc_dir_entry *entry;
    entry = proc_create(LKM_INTERFACE_FILE_PROC, 0666, NULL, &file_ops);
    if(!entry) return entry;
    file_ops.owner = THIS_MODULE;
    file_ops.write = write;
    file_ops.read = read;
    return entry;
}
#else
static struct proc_ops file_ops;
static struct proc_dir_entry *init_procfile(void) {
    struct proc_dir_entry *entry;
    entry = proc_create(LKM_INTERFACE_FILE_PROC, 0666, NULL, &file_ops);
    if(!entry) return entry;
    file_ops.proc_write = write;
    file_ops.proc_read = read;
    return entry;
}
#endif

static void remove_procfile(void) {
    remove_proc_entry(LKM_INTERFACE_FILE_PROC, NULL);
}


static int hello_init(void)
{
    struct proc_dir_entry *entry;
    entry = init_procfile();
    if(!entry) return -ENOENT;

    printk(KERN_ALERT "Hello, world\n");

//     configureSyscallRedirection();

    return 0;
}


static void hello_exit(void)
{
    remove_procfile();
    restorSyscallRedirection();
    printk(KERN_ALERT "Goodbye, you awesome people\n");
}


module_init(hello_init);
module_exit(hello_exit);

