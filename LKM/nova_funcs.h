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

#define NOVA_BASE_VERIFY(_) current->real_parent->pid != nova_ppid

static int verify_open(const char __user *filename, int flags, umode_t mode) {
//     printk(KERN_WARNING "serverless: open, %s, %d, %d, %d, %d, %d\n", current->comm, current->pid, current->cred->uid.val, current->parent->pid, current->group_leader->pid, current->tgid);
    return strcmp(current->comm, current->parent->comm) == 0;
//     return 0;
}
#define NOVA_HANDLED_VERIFY_open verify_open

#define NOVA_POST_PROC(__x__) \
    printk(KERN_WARNING "serverless: %s, %s, %d, %d, %d, %d, %d\n", #__x__,  current->comm, current->pid, current->cred->uid.val, current->parent->pid, current->group_leader->pid, current->tgid)
