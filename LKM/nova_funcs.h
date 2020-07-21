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

#define GET_CURRENT_EGID() from_kgid(current_user_ns(), current_egid())

#define NOVA_BASE_VERIFY(_) (IS_SAME_AS_NOVA_ID(GET_CURRENT_EGID()))

// static int verify_open(const char __user *filename, int flags, umode_t mode) {
//     return strcmp(current->comm, current->parent->comm) == 0;
// }
// #define NOVA_HANDLED_VERIFY_open verify_open

static int custom_verify_common(const char *syscall, int syscallnum) {
    nova_id_t gid = GET_CURRENT_EGID();
    printk(KERN_WARNING "syscall: %s, comm: %s, egid: %d, pid: %d, ppid: %d, glpid: %d, tgid: %d\n", syscall, current->comm, gid, current->pid, current->parent->pid, current->group_leader->pid, current->tgid);
    return IS_SAME_AS_NOVA_ID(gid);
}
#define NOVA_HANDLED_VERIFY(__x__) \
    custom_verify_common(#__x__, __NR_ ## __x__)

