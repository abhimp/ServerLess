#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
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
#include "nova_util.h"
#include "nova_uapi.h"
#include "nova_interface.h"

MODULE_LICENSE("GPL");


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

static int configureSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    sys_call_ptr_t *sys_call_table;

    if(!CAN_REDIRECT_NOVA()) return -ENOENT; // should not have any effect

    if(redirectionConfigured) return -ENOENT;
    redirectionConfigured = 1;

    sys_call_table = (sys_call_ptr_t *) kallsyms_lookup_name(sym_name);

    //TODO add a loop
    novaStoreAllOrigSysCalls(sys_call_table);

    CR0_WRITE_UNLOCK({
        novaRedirectAllSysCalls(sys_call_table);
    });
    printk(KERN_ALERT "tainted syscall added\n");
    return 0;
}

static void restorSyscallRedirection(void) {
    char *sym_name = "sys_call_table";
    sys_call_ptr_t *sys_call_table;

    if(!redirectionConfigured) return;
    redirectionConfigured = 0;

    sys_call_table = (sys_call_ptr_t *) kallsyms_lookup_name(sym_name);

    CR0_WRITE_UNLOCK({
        novaRestoreAllSysCall(sys_call_table);

    });

    printk(KERN_ALERT "tainted syscall removed\n");
}

static ssize_t write(struct file *file, const char *buf, size_t count, loff_t *pos) {
    struct nova_user2lkm myorder;
    if(!buf || !count) return -EINVAL;
    if(count < sizeof(myorder)) return -EINVAL;
    if(redirectionConfigured) return -EBUSY;
    return novaIsoSetParam(buf, count);
}

static ssize_t read(struct file *file, char *buf, size_t count, loff_t *pos) {
    int ret = 0;
    char buffer[32];
    if(!buf || !count) return -EINVAL;
    if(count < 20 || *pos < 0) return -EINVAL;
    if(*pos >= 20) return 0;

    ret = snprintf(buffer, 32, "%ld %ld\n", novaGetNumFunctionRedirected(), novaGetActiveRedirections());

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
    // remove_proc_entry("nova_cwd", NULL);
}



static struct current_working_directory {
    bool written;
    char *path;
};

static int open_cwd(struct inode *inode, struct file* file) {
    printk(KERN_DEBUG "In open\n");
    return 0;
}

static ssize_t write_cwd(struct file *file, const char *buf, size_t count, loff_t *pos) {
    if(file->private_data)
        kfree(file->private_data);
    file->private_data = kmalloc(sizeof(struct current_working_directory), GFP_KERNEL);
    ((struct current_working_directory *)(file->private_data))->written = true;
    int i;
    ((struct current_working_directory *)(file->private_data))->path = kmalloc(50, GFP_KERNEL);
    for(i = 0; i<strlen(buf); i++)
        ((struct current_working_directory *)(file->private_data))->path[i] = buf[i];
    ((struct current_working_directory *)(file->private_data))->path[strlen(buf)] = '\0';
    printk(KERN_INFO "Wrote %s to private_data\n", ((struct current_working_directory *)(file->private_data))->path);
    return strlen(buf) + 1;
}

static ssize_t read_cwd(struct file *file, char *buf, size_t count, loff_t *pos) {
    printk(KERN_INFO "Read %s from private_data\n", ((struct current_working_directory *)(file->private_data))->path);
    return 0;
}

static int release(struct inode *inode, struct file *file) {
    if(file->private_data)
        kfree(file->private_data);
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
static struct file_operations file_ops;
static struct proc_dir_entry *init_cwd_procfile(void) {
    struct proc_dir_entry *entry;
    entry = proc_create("nova_cwd", 0666, NULL, &file_ops);
    if(!entry) return entry;
    file_ops.owner = THIS_MODULE;
    file_ops.write = write_cwd;
    file_ops.read = read_cwd;
    file_ops.release = release;
    return entry;
}
#else
static struct proc_ops file_ops;
static struct proc_dir_entry *init_cwd_procfile(void) {
    struct proc_dir_entry *entry;
    entry = proc_create("nova_cwd", 0666, NULL, &file_ops);
    if(!entry) return entry;
    file_ops.proc_write = write_cwd;
    file_ops.proc_read = read_cwd;
    file_ops.release = release;
    return entry;
}
#endif


static int hello_init(void)
{
    struct proc_dir_entry *entry;
    // struct proc_dir_entry *cwd_entry;
    entry = init_procfile();
    if(!entry) return -ENOENT;
    // cwd_entry = init_cwd_procfile();
    // if(!cwd_entry)
    //     return -ENOENT;
    printk(KERN_ALERT "Hello, world\n");

//     configureSyscallRedirection();
    novaInitVerifier();

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

