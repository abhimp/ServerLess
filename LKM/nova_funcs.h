/****************************************************
 * Please follow proper method
 *
 * NOVA_PREPROC_<syscall>  for preprocessing
 * NOVA_BASE_VERIFY_<syscall> for basic verification. Be very carefull about this one. Need to be fast.
 * NOVA_HANDLED_VERIFY_<syscall> for 2nd level of verification, called only if base verification fails
 * NOVA_POST_PROC_<syscall> for post processing. Called only is base verification fails.
 *
 * All the functions recv same number of argument as the system call. verification macros are expected to be return 0 or 1 only.
 */

#define NOVA_BASE_VERIFY(_) (current->real_parent->pid != nova_ppid && current->pid != nova_ppid)

// static int verify_open(const char __user *filename, int flags, umode_t mode) {
//     return strcmp(current->comm, current->parent->comm) == 0;
// }
// #define NOVA_HANDLED_VERIFY_open verify_open

static int custom_verify_common(const char *syscall, int syscallnum) {
    printk(KERN_WARNING "syscall: %s, comm: %s, pid: %d, ppid: %d, glpid: %d, tgid: %d\n", syscall, current->comm, current->pid, current->parent->pid, current->group_leader->pid, current->tgid);
    return strcmp(current->comm, current->parent->comm) == 0 || current->pid == nova_ppid;
}
#define NOVA_HANDLED_VERIFY(__x__) \
    custom_verify_common(#__x__, __NR_ ## __x__)

// #define NOVA_HANDLED_VERIFY(_) (strcmp(current->comm, current->parent->comm) == 0)

// #define NOVA_POST_PROC(__x__)
//     printk(KERN_WARNING "serverless: %s, %s, %d, %d, %d, %d, %d\n", #__x__,  current->comm, current->pid, current->cred->uid.val, current->parent->pid, current->group_leader->pid, current->tgid)


// static int custom_verify_access(const char __user *filename, int mode) {
// }
#define NOVA_HANDLED_VERIFY_access(f, m)\
    (printk(KERN_WARNING "ACCESS, comm: %s, fp: %s, mode: %d, pid: %d, ppid: %d\n", current->comm, f, m, current->pid, current->parent->pid), (current->pid == nova_ppid || strcmp(current->comm, current->parent->comm) == 0))

#define NOVA_HANDLED_VERIFY_open(f, _,  m)\
    (printk(KERN_WARNING "OPEN, comm: %s, fp: %s, mode: %d, pid: %d, ppid: %d\n", current->comm, f, m, current->pid, current->parent->pid), (current->pid == nova_ppid || strcmp(current->comm, current->parent->comm) == 0))

#define NOVA_HANDLED_VERIFY_stat(f, _)\
    (printk(KERN_WARNING "STAT, comm: %s, fp: %s, pid: %d, ppid: %d\n", current->comm, f, current->pid, current->parent->pid), (current->pid == nova_ppid || strcmp(current->comm, current->parent->comm) == 0))

//nova_sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru)
#define NOVA_HANDLED_VERIFY_waitid(w, p, i, o, r) \
    (printk(KERN_WARNING "WAITID, comm: %s, which: %d, pida: %d, infop: %p, options: %d, ru: %p, pid: %d, ppid: %d\n", current->comm, w, p, i, o, r, current->pid, current->parent->pid), (current->pid == nova_ppid || strcmp(current->comm, current->parent->comm) == 0))

//unsigned long fn, unsigned long stack, int __user *flags, unsigned long arg, int __user *arg2
#define NOVA_HANDLED_VERIFY_clone(fn, st, fl, a, a2) \
    (printk(KERN_WARNING "CLONE, comm: %s, fn: %lu, st: %lu, fl: %d, pid: %d, ppid: %d\n", current->comm, fn, st, fl? *fl : 0, current->pid, current->parent->pid), (current->pid == nova_ppid || strcmp(current->comm, current->parent->comm) == 0))

#define NOVA_POST_PROC_clone(fn, st, fl, a, a2) \
    (printk(KERN_WARNING "CLONE-post, comm: %s, fn: %lu, st: %lu, fl: %d, pid: %d, ppid: %d\n", current->comm, fn, st, fl? *fl : 0, current->pid, current->parent->pid))
