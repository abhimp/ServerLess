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

static struct proc_ops file_ops;
static char buffer[256] = {0}; static int buffer_len = 0;

static ssize_t write(struct file *file, const char *buf, size_t count, loff_t *pos) {
    if(!buf || !count) return -EINVAL;
    if(copy_from_user(buffer, buf, count < 256 ? count:256)) return -ENOBUFS;

    buffer_len = count < 256 ? count:256;
    printk(KERN_INFO "%.*s", (int)count, buf);
    return buffer_len;
}

static ssize_t read(struct file *file, char *buf, size_t count, loff_t *pos) {
    int ret = buffer_len;
    if(!buffer_len) return 0;
    if(!buf || !count) return -EINVAL;
    if(copy_to_user(buf, buffer, buffer_len)) return -ENOBUFS;

    printk(KERN_INFO "%.*s", (int)buffer_len, buffer);
    buffer_len = 0;
    return ret;
}

static void configureSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    void **sys_call_table;

    sys_call_table = (void *) kallsyms_lookup_name(sym_name);

    //TODO add a loop
    NOVA_STORE_ORIG(open, sys_call_table);

    write_cr0(read_cr0() & (~0x10000)); //remove write protection

    //TODO add another loop
    NOVA_REDIRECT(open, sys_call_table);

    write_cr0(read_cr0() | 0x10000); //restore write protection
}

static void restorSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    void **sys_call_table;

    sys_call_table = (void **) kallsyms_lookup_name(sym_name);

    write_cr0(read_cr0() & (~0x10000)); //remove write protection

    //TODO add another loop
    NOVA_RESTORE(open, sys_call_table);

    write_cr0(read_cr0() | 0x10000); //restore write protection
}

static int hello_init(void)
{
    struct proc_dir_entry *entry;

    printk(KERN_ALERT "Hello, world\n");
    entry = proc_create(LKM_INTERFACE_FILE_PROC, 0666, NULL, &file_ops);
    if(!entry) return -ENOENT;
//     file_ops.owner = THIS_MODULE;
    file_ops.proc_write = write;
    file_ops.proc_read = read;

    configureSyscallRedirection();

    return 0;
}


static void hello_exit(void)
{
    remove_proc_entry(LKM_INTERFACE_FILE_PROC, NULL);
    restorSyscallRedirection();
    printk(KERN_ALERT "Goodbye, you awesome people\n");
}


module_init(hello_init);
module_exit(hello_exit);

