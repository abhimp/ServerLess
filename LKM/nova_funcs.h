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
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#define GET_CURRENT_EGID() current_egid()

#define NOVA_BASE_VERIFY(_) (!IS_SAME_AS_NOVA_ID(GET_CURRENT_EGID()))

// static int verify_open(const char __user *filename, int flags, umode_t mode) {
//     return strcmp(current->comm, current->parent->comm) == 0;
// }
// #define NOVA_HANDLED_VERIFY_open verify_open

static int custom_verify_common(const char *syscall, int syscallnum) {
    nova_id_t gid = from_kgid(current_user_ns(), current_egid());
    printk(KERN_WARNING "syscall: %s, comm: %s, egid: %d, pid: %d, ppid: %d, glpid: %d, tgid: %d\n", syscall, current->comm, gid, current->pid, current->parent->pid, current->group_leader->pid, current->tgid);
    return !IS_SAME_AS_NOVA_ID(GET_CURRENT_EGID());
}
#define NOVA_HANDLED_VERIFY(__x__) \
    custom_verify_common(#__x__, __NR_ ## __x__)

#define NOVA_HANDLED_VERIFY_setreuid(ruid, euid) \
            (from_kuid(current_user_ns(), current_euid()) == 0)

//strcmp(current->comm, current->parent->comm)
#define NOVA_HANDLED_VERIFY_execve(a, b, c) \
    (current->parent->pid == monitorPid && strcmp(current->comm, current->parent->comm) == 0)


// custom debuggers to trace system call arguments
/*
#define NOVA_PRE_PROC_openat(dirfd, pathname, flags, mode) \
    printk(KERN_WARNING "syscall: openat, dirfd: %d, pathname: %s, flags: %d, mode: %o\n", dirfd, pathname, flags, mode)
    if(dirfd != 100 && ((ret = print_filename(dirfd)) != 0)) printk(KERN_WARNING "error in print_filename %d\n", ret);\
*/
#define NOVA_PRE_PROC_openat(dirfd, pathname, flags, mode) {\
    int ret;\
    char full_path[200];\
    ret = get_full_path(dirfd, pathname, full_path);\
    printk(KERN_WARNING "syscall: openat, dirfd: %d, pathname: %s, flags: %d, mode: %o\n", dirfd, pathname, flags, mode);\
}

/*
#define NOVA_PRE_PROC_clone(fn, stack, flags, arg, arg2) \
    printk(KERN_WARNING "syscall: clone, fn: %ld, stack: %ld, flags: %u, arg: \n", fn, stack, flags)

#define NOVA_PRE_PROC_socket(domain, type, protocol) \
    printk(KERN_WARNING "syscall: socket, domain: %d, type: %d, protocol: %d\n", domain, type, protocol)
*/

static int print_filename(int fd) {
    char *tmp;
    char *pathname;
    struct file *file;
    struct path *path;
    struct files_struct *files = current->files;
    spin_lock(&files->file_lock);
    file = fcheck_files(files, fd);
    if (!file) {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }
    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);
    tmp = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp) {
        path_put(path);
        return -ENOMEM;
    }
    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(path);
    if (IS_ERR(pathname)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }
    printk(KERN_WARNING "fd %d's filename: %s\n", fd, pathname);
    free_page((unsigned long)tmp);
    return 0;
}

static int get_pwd_as_string(char pwd[]) {
    char *tmp;
    char *pathname;
    int i;
    
    struct path path;
    get_fs_pwd(current->fs, &path);
    tmp = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp) {
        path_put(&path);
        return -ENOMEM;
    }
    pathname = d_path(&path, tmp, PAGE_SIZE);
    path_put(&path);
    if (IS_ERR(pathname)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }
    
    printk("pwd is: %s\n", pathname);
    strcpy(&pwd[0], pathname);
    free_page((unsigned long)tmp);

    return 0;
}

static int get_full_path(int fd, const char *rel_path, char *full_path) {
    

    // handle using get_fs_root_and_pwd
    char *tmp;
    char *pathname;
    struct file *file;
    int i;
    struct path *path;
    struct files_struct *files;
    // return in case of absolute path
    if(rel_path[0] == '/') {
        strcpy(full_path, rel_path);
        return 0;
    }
    if(fd == AT_FDCWD) {
        int i, ret;
        char pwd[200];
        ret = get_pwd_as_string(pwd);
        if(ret < 0)
            return ret;
        for(i = 0; i<strlen(pwd); i++)
            full_path[i] = pwd[i];
        full_path[strlen(pwd)] = '/';

        for(i = 0; i<strlen(rel_path); i++)
            full_path[i + strlen(pwd) + 1] = rel_path[i];
        full_path[strlen(rel_path) + strlen(pwd) + 1] = '\0';
        printk(KERN_WARNING "full_path: %s\n", full_path);
        return 0;
    }
    files = current->files;
    spin_lock(&files->file_lock);
    file = fcheck_files(files, fd);
    if (!file) {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }
    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);
    tmp = (char *)__get_free_page(GFP_KERNEL);
    if (!tmp) {
        path_put(path);
        return -ENOMEM;
    }
    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(path);
    if (IS_ERR(pathname)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(pathname);
    }
    for(i = 0; i<strlen(pathname); i++)
        full_path[i] = pathname[i];
    full_path[strlen(pathname)] = '/';
    for(i = 0; i<strlen(rel_path); i++)
        full_path[i + strlen(pathname) + 1] = rel_path[i];
    full_path[strlen(rel_path) + strlen(pathname) + 1] = '\0';
    printk(KERN_WARNING "full_path: %s\n", full_path);
    free_page((unsigned long)tmp);
    return 0;
}

//input: "a/b/../c" -> "a/c"
static int sanitize_path(char *path) {
    char *ip, *op, *init;

    for(op=path, ip=path; *ip; ip++, op++) { //strip //+
        for(;*ip == '/' && ip[1] == '/'; ip++);
        *op = *ip;
    }
    *op = 0;

    op = ip = path;
    if(*ip == '/') ip++;

    op = ip;
    init = ip;

    while(*ip) {
        if(ip[0] == '.' && ip[1] == '/') {
            ip += 2;
            continue;
        }
        if(ip[0] == '.' && ip[1] == '.' && (ip[2] == '/' || ip[2] == 0)) {
            if(op != init) {
                op -= 2;
                while(op != init && *(op-1) != '/'){
                    op --;
                }
                ip += ip[2] == 0 ? 2 : 3;
            }
            else {
                *op = *ip; op++; ip++;
                *op = *ip; op++; ip++;
                *op = *ip; op++; ip++;
                init = op;
            }
            continue;
        }
        while(*ip != '/'){
            *op = *ip; op++; ip++;
        }
        *op = *ip; op++; ip++;
    }
    *op = 0;

    return 0;
}

static int validate_path(char *path, mode_t mode) {
    int ret;
    if((ret = sanitize_path(path)) < 0)
        return ret;
    if(strncmp(path, "/..", 3) == 0) // trying to access outside the location. Although I don't have to bother about it, vfs will take care of it.
        return -EINVAL;
    if(strncmp(path, novaIsoHomePath, novaIsoHomePathLen) == 0)
        return 0;
}
