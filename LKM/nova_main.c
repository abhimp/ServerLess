#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define LKM_INTERFACE_FILE_PROC "hello"

static struct file_operations file_ops;
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

static int hello_init(void)
{
    printk(KERN_ALERT "Hello, world\n");
    struct proc_dir_entry *entry = proc_create(LKM_INTERFACE_FILE_PROC, 0, NULL, &file_ops);
    if(!entry) return -ENOENT;
    file_ops.owner = THIS_MODULE;
    file_ops.write = write;
    file_ops.read = read;
    return 0;
}


static void hello_exit(void)
{
    remove_proc_entry(LKM, NULL);
    printk(KERN_ALERT "Goodbye, you awesome people\n");
}


module_init(hello_init);
module_exit(hello_exit);

