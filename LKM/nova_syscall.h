//==============================
asmlinkage long
nova_sys_open(const char __user *filename, int flags, umode_t mode) {
	return sys_open(filename, flags, mode);
}

//==============================
asmlinkage long
nova_sys_newstat(const char __user *filename, struct stat __user *statbuf) {
	return sys_newstat(filename, statbuf);
}

//==============================
asmlinkage long
nova_sys_newfstat(unsigned int fd, struct stat __user *statbuf) {
	return sys_newfstat(fd, statbuf);
}

//==============================
asmlinkage long
nova_sys_newlstat(const char __user *filename, struct stat __user *statbuf) {
	return sys_newlstat(filename, statbuf);
}

//==============================
asmlinkage long
nova_sys_access(const char __user *filename, int mode) {
	return sys_access(filename, mode);
}

//==============================
asmlinkage long
nova_sys_pipe(int __user *fildes) {
	return sys_pipe(fildes);
}

//==============================
asmlinkage long
nova_sys_shmget(key_t key, size_t size, int flag) {
	return sys_shmget(key, size, flag);
}

//==============================
asmlinkage long
nova_sys_shmat(int shmid, char __user *shmaddr, int shmflg) {
	return sys_shmat(shmid, shmaddr, shmflg);
}

//==============================
asmlinkage long
nova_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf) {
	return sys_shmctl(shmid, cmd, buf);
}

//==============================
asmlinkage long
nova_sys_dup(unsigned int fildes) {
	return sys_dup(fildes);
}

//==============================
asmlinkage long
nova_sys_dup2(unsigned int oldfd, unsigned int newfd) {
	return sys_dup2(oldfd, newfd);
}

//==============================
asmlinkage long
nova_sys_pause(void) {
	return sys_pause();
}

//==============================
asmlinkage long
nova_sys_socket(int, int, int) {
	return sys_socket(int, int, int);
}

//==============================
asmlinkage long
nova_sys_accept(int, struct sockaddr __user *, int __user *) {
	return sys_accept(int, , );
}

//==============================
asmlinkage long
nova_sys_bind(int, struct sockaddr __user *, int) {
	return sys_bind(int, , int);
}

//==============================
asmlinkage long
nova_sys_listen(int, int) {
	return sys_listen(int, int);
}

//==============================
asmlinkage long
nova_sys_socketpair(int, int, int, int __user *) {
	return sys_socketpair(int, int, int, );
}

//==============================
asmlinkage long
nova_sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen) {
	return sys_setsockopt(fd, level, optname, optval, optlen);
}

//==============================
asmlinkage long
nova_sys_clone(unsigned long, unsigned long, int __user *, unsigned long, int __user *) {
	return sys_clone(long, long, , long, );
}

//==============================
asmlinkage long
nova_sys_fork(void) {
	return sys_fork();
}

//==============================
asmlinkage long
nova_sys_vfork(void) {
	return sys_vfork();
}

//==============================
asmlinkage long
nova_sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
	return sys_execve(filename, argv, envp);
}

//==============================
asmlinkage long
nova_sys_exit(int error_code) {
	return sys_exit(error_code);
}

//==============================
asmlinkage long
nova_sys_kill(pid_t pid, int sig) {
	return sys_kill(pid, sig);
}

//==============================
asmlinkage long
nova_sys_semget(key_t key, int nsems, int semflg) {
	return sys_semget(key, nsems, semflg);
}

//==============================
asmlinkage long
nova_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops) {
	return sys_semop(semid, sops, nsops);
}

//==============================
asmlinkage long
nova_sys_semctl(int semid, int semnum, int cmd, unsigned long arg) {
	return sys_semctl(semid, semnum, cmd, arg);
}

//==============================
asmlinkage long
nova_sys_shmdt(char __user *shmaddr) {
	return sys_shmdt(shmaddr);
}

//==============================
asmlinkage long
nova_sys_msgget(key_t key, int msgflg) {
	return sys_msgget(key, msgflg);
}

//==============================
asmlinkage long
nova_sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg) {
	return sys_msgsnd(msqid, msgp, msgsz, msgflg);
}

//==============================
asmlinkage long
nova_sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg) {
	return sys_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
}

//==============================
asmlinkage long
nova_sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf) {
	return sys_msgctl(msqid, cmd, buf);
}

//==============================
asmlinkage long
nova_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) {
	return sys_fcntl(fd, cmd, arg);
}

//==============================
asmlinkage long
nova_sys_truncate(const char __user *path, long length) {
	return sys_truncate(path, length);
}

//==============================
asmlinkage long
nova_sys_ftruncate(unsigned int fd, unsigned long length) {
	return sys_ftruncate(fd, length);
}

//==============================
asmlinkage long
nova_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	return sys_getdents(fd, dirent, count);
}

//==============================
asmlinkage long
nova_sys_getcwd(char __user *buf, unsigned long size) {
	return sys_getcwd(buf, size);
}

//==============================
asmlinkage long
nova_sys_chdir(const char __user *filename) {
	return sys_chdir(filename);
}

//==============================
asmlinkage long
nova_sys_fchdir(unsigned int fd) {
	return sys_fchdir(fd);
}

//==============================
asmlinkage long
nova_sys_rename(const char __user *oldname, const char __user *newname) {
	return sys_rename(oldname, newname);
}

//==============================
asmlinkage long
nova_sys_mkdir(const char __user *pathname, umode_t mode) {
	return sys_mkdir(pathname, mode);
}

//==============================
asmlinkage long
nova_sys_rmdir(const char __user *pathname) {
	return sys_rmdir(pathname);
}

//==============================
asmlinkage long
nova_sys_creat(const char __user *pathname, umode_t mode) {
	return sys_creat(pathname, mode);
}

//==============================
asmlinkage long
nova_sys_link(const char __user *oldname, const char __user *newname) {
	return sys_link(oldname, newname);
}

//==============================
asmlinkage long
nova_sys_unlink(const char __user *pathname) {
	return sys_unlink(pathname);
}

//==============================
asmlinkage long
nova_sys_symlink(const char __user *old, const char __user *new) {
	return sys_symlink(old, new);
}

//==============================
asmlinkage long
nova_sys_readlink(const char __user *path, char __user *buf, int bufsiz) {
	return sys_readlink(path, buf, bufsiz);
}

//==============================
asmlinkage long
nova_sys_chmod(const char __user *filename, umode_t mode) {
	return sys_chmod(filename, mode);
}

//==============================
asmlinkage long
nova_sys_fchmod(unsigned int fd, umode_t mode) {
	return sys_fchmod(fd, mode);
}

//==============================
asmlinkage long
nova_sys_chown(const char __user *filename, uid_t user, gid_t group) {
	return sys_chown(filename, user, group);
}

//==============================
asmlinkage long
nova_sys_fchown(unsigned int fd, uid_t user, gid_t group) {
	return sys_fchown(fd, user, group);
}

//==============================
asmlinkage long
nova_sys_lchown(const char __user *filename, uid_t user, gid_t group) {
	return sys_lchown(filename, user, group);
}

//==============================
asmlinkage long
nova_sys_umask(int mask) {
	return sys_umask(mask);
}

//==============================
asmlinkage long
nova_sys_sysinfo(struct sysinfo __user *info) {
	return sys_sysinfo(info);
}

//==============================
asmlinkage long
nova_sys_ptrace(long request, long pid, unsigned long addr, unsigned long data) {
	return sys_ptrace(request, pid, addr, data);
}

//==============================
asmlinkage long
nova_sys_setuid(uid_t uid) {
	return sys_setuid(uid);
}

//==============================
asmlinkage long
nova_sys_setgid(gid_t gid) {
	return sys_setgid(gid);
}

//==============================
asmlinkage long
nova_sys_setpgid(pid_t pid, pid_t pgid) {
	return sys_setpgid(pid, pgid);
}

//==============================
asmlinkage long
nova_sys_setsid(void) {
	return sys_setsid();
}

//==============================
asmlinkage long
nova_sys_setreuid(uid_t ruid, uid_t euid) {
	return sys_setreuid(ruid, euid);
}

//==============================
asmlinkage long
nova_sys_setregid(gid_t rgid, gid_t egid) {
	return sys_setregid(rgid, egid);
}

//==============================
asmlinkage long
nova_sys_setgroups(int gidsetsize, gid_t __user *grouplist) {
	return sys_setgroups(gidsetsize, grouplist);
}

//==============================
asmlinkage long
nova_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	return sys_setresuid(ruid, euid, suid);
}

//==============================
asmlinkage long
nova_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	return sys_setresgid(rgid, egid, sgid);
}

//==============================
asmlinkage long
nova_sys_setfsuid(uid_t uid) {
	return sys_setfsuid(uid);
}

//==============================
asmlinkage long
nova_sys_setfsgid(gid_t gid) {
	return sys_setfsgid(gid);
}

//==============================
asmlinkage long
nova_sys_capset(cap_user_header_t header, const cap_user_data_t data) {
	return sys_capset(header, data);
}

//==============================
asmlinkage long
nova_sys_utime(char __user *filename, struct utimbuf __user *times) {
	return sys_utime(filename, times);
}

//==============================
asmlinkage long
nova_sys_uselib(const char __user *library) {
	return sys_uselib(library);
}

//==============================
asmlinkage long
nova_sys_personality(unsigned int personality) {
	return sys_personality(personality);
}

//==============================
asmlinkage long
nova_sys_ustat(unsigned dev, struct ustat __user *ubuf) {
	return sys_ustat(dev, ubuf);
}

//==============================
asmlinkage long
nova_sys_statfs(const char __user * path, struct statfs __user *buf) {
	return sys_statfs(path, buf);
}

//==============================
asmlinkage long
nova_sys_fstatfs(unsigned int fd, struct statfs __user *buf) {
	return sys_fstatfs(fd, buf);
}

//==============================
asmlinkage long
nova_sys_sysfs(int option, unsigned long arg1, unsigned long arg2) {
	return sys_sysfs(option, arg1, arg2);
}

//==============================
asmlinkage long
nova_sys_getpriority(int which, int who) {
	return sys_getpriority(which, who);
}

//==============================
asmlinkage long
nova_sys_setpriority(int which, int who, int niceval) {
	return sys_setpriority(which, who, niceval);
}

//==============================
asmlinkage long
nova_sys_sched_setparam(pid_t pid, struct sched_param __user *param) {
	return sys_sched_setparam(pid, param);
}

//==============================
asmlinkage long
nova_sys_sched_getparam(pid_t pid, struct sched_param __user *param) {
	return sys_sched_getparam(pid, param);
}

//==============================
asmlinkage long
nova_sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param) {
	return sys_sched_setscheduler(pid, policy, param);
}

//==============================
asmlinkage long
nova_sys_sched_getscheduler(pid_t pid) {
	return sys_sched_getscheduler(pid);
}

//==============================
asmlinkage long
nova_sys_sched_get_priority_max(int policy) {
	return sys_sched_get_priority_max(policy);
}

//==============================
asmlinkage long
nova_sys_sched_get_priority_min(int policy) {
	return sys_sched_get_priority_min(policy);
}

//==============================
asmlinkage long
nova_sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval) {
	return sys_sched_rr_get_interval(pid, interval);
}

//==============================
asmlinkage long
nova_sys_vhangup(void) {
	return sys_vhangup();
}

//==============================
asmlinkage long
nova_sys_modify_ldt(int, void __user *, unsigned long) {
	return sys_modify_ldt(int, , long);
}

//==============================
asmlinkage long
nova_sys_pivot_root(const char __user *new_root, const char __user *put_old) {
	return sys_pivot_root(new_root, put_old);
}

//==============================
asmlinkage long
nova_sys_sysctl(struct __sysctl_args __user *args) {
	return sys_sysctl(args);
}

//==============================
asmlinkage long
nova_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	return sys_prctl(option, arg2, arg3, arg4, arg5);
}

//==============================
asmlinkage long
nova_sys_adjtimex(struct __kernel_timex __user *txc_p) {
	return sys_adjtimex(txc_p);
}

//==============================
asmlinkage long
nova_sys_setrlimit(unsigned int resource, struct rlimit __user *rlim) {
	return sys_setrlimit(resource, rlim);
}

//==============================
asmlinkage long
nova_sys_chroot(const char __user *filename) {
	return sys_chroot(filename);
}

//==============================
asmlinkage long
nova_sys_sync(void) {
	return sys_sync();
}

//==============================
asmlinkage long
nova_sys_acct(const char __user *name) {
	return sys_acct(name);
}

//==============================
asmlinkage long
nova_sys_settimeofday(struct timeval __user *tv, struct timezone __user *tz) {
	return sys_settimeofday(tv, tz);
}

//==============================
asmlinkage long
nova_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data) {
	return sys_mount(dev_name, dir_name, type, flags, data);
}

//==============================
asmlinkage long
nova_sys_umount(char __user *name, int flags) {
	return sys_umount(name, flags);
}

//==============================
asmlinkage long
nova_sys_swapon(const char __user *specialfile, int swap_flags) {
	return sys_swapon(specialfile, swap_flags);
}

//==============================
asmlinkage long
nova_sys_swapoff(const char __user *specialfile) {
	return sys_swapoff(specialfile);
}

//==============================
asmlinkage long
nova_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg) {
	return sys_reboot(magic1, magic2, cmd, arg);
}

//==============================
asmlinkage long
nova_sys_sethostname(char __user *name, int len) {
	return sys_sethostname(name, len);
}

//==============================
asmlinkage long
nova_sys_setdomainname(char __user *name, int len) {
	return sys_setdomainname(name, len);
}

//==============================
asmlinkage long
nova_sys_iopl(unsigned int) {
	return sys_iopl(int);
}

//==============================
asmlinkage long
nova_sys_ioperm(unsigned long from, unsigned long num, int on) {
	return sys_ioperm(from, num, on);
}

//==============================
asmlinkage long
nova_sys_init_module(void __user *umod, unsigned long len, const char __user *uargs) {
	return sys_init_module(umod, len, uargs);
}

//==============================
asmlinkage long
nova_sys_delete_module(const char __user *name_user, unsigned int flags) {
	return sys_delete_module(name_user, flags);
}

//==============================
asmlinkage long
nova_sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr) {
	return sys_quotactl(cmd, special, id, addr);
}

//==============================
asmlinkage long
nova_sys_gettid(void) {
	return sys_gettid();
}

//==============================
asmlinkage long
nova_sys_readahead(int fd, loff_t offset, size_t count) {
	return sys_readahead(fd, offset, count);
}

//==============================
asmlinkage long
nova_sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags) {
	return sys_setxattr(path, name, value, size, flags);
}

//==============================
asmlinkage long
nova_sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags) {
	return sys_lsetxattr(path, name, value, size, flags);
}

//==============================
asmlinkage long
nova_sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags) {
	return sys_fsetxattr(fd, name, value, size, flags);
}

//==============================
asmlinkage long
nova_sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size) {
	return sys_getxattr(path, name, value, size);
}

//==============================
asmlinkage long
nova_sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size) {
	return sys_lgetxattr(path, name, value, size);
}

//==============================
asmlinkage long
nova_sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size) {
	return sys_fgetxattr(fd, name, value, size);
}

//==============================
asmlinkage long
nova_sys_listxattr(const char __user *path, char __user *list, size_t size) {
	return sys_listxattr(path, list, size);
}

//==============================
asmlinkage long
nova_sys_llistxattr(const char __user *path, char __user *list, size_t size) {
	return sys_llistxattr(path, list, size);
}

//==============================
asmlinkage long
nova_sys_flistxattr(int fd, char __user *list, size_t size) {
	return sys_flistxattr(fd, list, size);
}

//==============================
asmlinkage long
nova_sys_removexattr(const char __user *path, const char __user *name) {
	return sys_removexattr(path, name);
}

//==============================
asmlinkage long
nova_sys_lremovexattr(const char __user *path, const char __user *name) {
	return sys_lremovexattr(path, name);
}

//==============================
asmlinkage long
nova_sys_fremovexattr(int fd, const char __user *name) {
	return sys_fremovexattr(fd, name);
}

//==============================
asmlinkage long
nova_sys_tkill(pid_t pid, int sig) {
	return sys_tkill(pid, sig);
}

//==============================
asmlinkage long
nova_sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) {
	return sys_sched_setaffinity(pid, len, user_mask_ptr);
}

//==============================
asmlinkage long
nova_sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) {
	return sys_sched_getaffinity(pid, len, user_mask_ptr);
}

//==============================
asmlinkage long
nova_sys_set_thread_area(struct user_desc __user *) {
	return sys_set_thread_area();
}

//==============================
asmlinkage long
nova_sys_get_thread_area(struct user_desc __user *) {
	return sys_get_thread_area();
}

//==============================
asmlinkage long
nova_sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len) {
	return sys_lookup_dcookie(cookie64, buf, len);
}

//==============================
asmlinkage long
nova_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
	return sys_getdents64(fd, dirent, count);
}

//==============================
asmlinkage long
nova_sys_set_tid_address(int __user *tidptr) {
	return sys_set_tid_address(tidptr);
}

//==============================
asmlinkage long
nova_sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout) {
	return sys_semtimedop(semid, sops, nsops, timeout);
}

//==============================
asmlinkage long
nova_sys_fadvise64(int fd, loff_t offset, size_t len, int advice) {
	return sys_fadvise64(fd, offset, len, advice);
}

//==============================
asmlinkage long
nova_sys_utimes(char __user *filename, struct timeval __user *utimes) {
	return sys_utimes(filename, utimes);
}

//==============================
asmlinkage long
nova_sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr) {
	return sys_mq_open(name, oflag, mode, attr);
}

//==============================
asmlinkage long
nova_sys_mq_unlink(const char __user *name) {
	return sys_mq_unlink(name);
}

//==============================
asmlinkage long
nova_sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *abs_timeout) {
	return sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

//==============================
asmlinkage long
nova_sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct __kernel_timespec __user *abs_timeout) {
	return sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

//==============================
asmlinkage long
nova_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification) {
	return sys_mq_notify(mqdes, notification);
}

//==============================
asmlinkage long
nova_sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat) {
	return sys_mq_getsetattr(mqdes, mqstat, omqstat);
}

//==============================
asmlinkage long
nova_sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags) {
	return sys_kexec_load(entry, nr_segments, segments, flags);
}

//==============================
asmlinkage long
nova_sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru) {
	return sys_waitid(which, pid, infop, options, ru);
}

//==============================
asmlinkage long
nova_sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid) {
	return sys_add_key(_type, _description, _payload, plen, destringid);
}

//==============================
asmlinkage long
nova_sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid) {
	return sys_request_key(_type, _description, _callout_info, destringid);
}

//==============================
asmlinkage long
nova_sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	return sys_keyctl(cmd, arg2, arg3, arg4, arg5);
}

//==============================
asmlinkage long
nova_sys_ioprio_set(int which, int who, int ioprio) {
	return sys_ioprio_set(which, who, ioprio);
}

//==============================
asmlinkage long
nova_sys_ioprio_get(int which, int who) {
	return sys_ioprio_get(which, who);
}

//==============================
asmlinkage long
nova_sys_inotify_init(void) {
	return sys_inotify_init();
}

//==============================
asmlinkage long
nova_sys_inotify_add_watch(int fd, const char __user *path, u32 mask) {
	return sys_inotify_add_watch(fd, path, mask);
}

//==============================
asmlinkage long
nova_sys_inotify_rm_watch(int fd, __s32 wd) {
	return sys_inotify_rm_watch(fd, wd);
}

//==============================
asmlinkage long
nova_sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to) {
	return sys_migrate_pages(pid, maxnode, from, to);
}

//==============================
asmlinkage long
nova_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode) {
	return sys_openat(dfd, filename, flags, mode);
}

//==============================
asmlinkage long
nova_sys_mkdirat(int dfd, const char __user * pathname, umode_t mode) {
	return sys_mkdirat(dfd, pathname, mode);
}

//==============================
asmlinkage long
nova_sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev) {
	return sys_mknodat(dfd, filename, mode, dev);
}

//==============================
asmlinkage long
nova_sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag) {
	return sys_fchownat(dfd, filename, user, group, flag);
}

//==============================
asmlinkage long
nova_sys_futimesat(int dfd, const char __user *filename, struct timeval __user *utimes) {
	return sys_futimesat(dfd, filename, utimes);
}

//==============================
asmlinkage long
nova_sys_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag) {
	return sys_newfstatat(dfd, filename, statbuf, flag);
}

//==============================
asmlinkage long
nova_sys_unlinkat(int dfd, const char __user * pathname, int flag) {
	return sys_unlinkat(dfd, pathname, flag);
}

//==============================
asmlinkage long
nova_sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname) {
	return sys_renameat(olddfd, oldname, newdfd, newname);
}

//==============================
asmlinkage long
nova_sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags) {
	return sys_linkat(olddfd, oldname, newdfd, newname, flags);
}

//==============================
asmlinkage long
nova_sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname) {
	return sys_symlinkat(oldname, newdfd, newname);
}

//==============================
asmlinkage long
nova_sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz) {
	return sys_readlinkat(dfd, path, buf, bufsiz);
}

//==============================
asmlinkage long
nova_sys_fchmodat(int dfd, const char __user * filename, umode_t mode) {
	return sys_fchmodat(dfd, filename, mode);
}

//==============================
asmlinkage long
nova_sys_faccessat(int dfd, const char __user *filename, int mode) {
	return sys_faccessat(dfd, filename, mode);
}

//==============================
asmlinkage long
nova_sys_pselect6(int, fd_set __user *, fd_set __user *, fd_set __user *, struct __kernel_timespec __user *, void __user *) {
	return sys_pselect6(int, , , , , );
}

//==============================
asmlinkage long
nova_sys_unshare(unsigned long unshare_flags) {
	return sys_unshare(unshare_flags);
}

//==============================
asmlinkage long
nova_sys_set_robust_list(struct robust_list_head __user *head, size_t len) {
	return sys_set_robust_list(head, len);
}

//==============================
asmlinkage long
nova_sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr) {
	return sys_get_robust_list(pid, head_ptr, len_ptr);
}

//==============================
asmlinkage long
nova_sys_utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags) {
	return sys_utimensat(dfd, filename, utimes, flags);
}

//==============================
asmlinkage long
nova_sys_eventfd(unsigned int count) {
	return sys_eventfd(count);
}

//==============================
asmlinkage long
nova_sys_fallocate(int fd, int mode, loff_t offset, loff_t len) {
	return sys_fallocate(fd, mode, offset, len);
}

//==============================
asmlinkage long
nova_sys_timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr) {
	return sys_timerfd_settime(ufd, flags, utmr, otmr);
}

//==============================
asmlinkage long
nova_sys_timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr) {
	return sys_timerfd_gettime(ufd, otmr);
}

//==============================
asmlinkage long
nova_sys_accept4(int, struct sockaddr __user *, int __user *, int) {
	return sys_accept4(int, , , int);
}

//==============================
asmlinkage long
nova_sys_eventfd2(unsigned int count, int flags) {
	return sys_eventfd2(count, flags);
}

//==============================
asmlinkage long
nova_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags) {
	return sys_dup3(oldfd, newfd, flags);
}

//==============================
asmlinkage long
nova_sys_pipe2(int __user *fildes, int flags) {
	return sys_pipe2(fildes, flags);
}

//==============================
asmlinkage long
nova_sys_inotify_init1(int flags) {
	return sys_inotify_init1(flags);
}

//==============================
asmlinkage long
nova_sys_perf_event_open(struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	return sys_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
}

//==============================
asmlinkage long
nova_sys_fanotify_init(unsigned int flags, unsigned int event_f_flags) {
	return sys_fanotify_init(flags, event_f_flags);
}

//==============================
asmlinkage long
nova_sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user *pathname) {
	return sys_fanotify_mark(fanotify_fd, flags, mask, fd, pathname);
}

//==============================
asmlinkage long
nova_sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim) {
	return sys_prlimit64(pid, resource, new_rlim, old_rlim);
}

//==============================
asmlinkage long
nova_sys_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag) {
	return sys_name_to_handle_at(dfd, name, handle, mnt_id, flag);
}

//==============================
asmlinkage long
nova_sys_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags) {
	return sys_open_by_handle_at(mountdirfd, handle, flags);
}

//==============================
asmlinkage long
nova_sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex __user *tx) {
	return sys_clock_adjtime(which_clock, tx);
}

//==============================
asmlinkage long
nova_sys_syncfs(int fd) {
	return sys_syncfs(fd);
}

//==============================
asmlinkage long
nova_sys_setns(int fd, int nstype) {
	return sys_setns(fd, nstype);
}

//==============================
asmlinkage long
nova_sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache) {
	return sys_getcpu(cpu, node, cache);
}

//==============================
asmlinkage long
nova_sys_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags) {
	return sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
}

//==============================
asmlinkage long
nova_sys_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags) {
	return sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
}

//==============================
asmlinkage long
nova_sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
	return sys_kcmp(pid1, pid2, type, idx1, idx2);
}

//==============================
asmlinkage long
nova_sys_finit_module(int fd, const char __user *uargs, int flags) {
	return sys_finit_module(fd, uargs, flags);
}


syscall_handler_t nova_syscall_table[NR_syscalls];
nova_syscall_table[NR_open] = nova_sys_open;
nova_syscall_table[NR_stat] = nova_sys_newstat;
nova_syscall_table[NR_fstat] = nova_sys_newfstat;
nova_syscall_table[NR_lstat] = nova_sys_newlstat;
nova_syscall_table[NR_access] = nova_sys_access;
nova_syscall_table[NR_pipe] = nova_sys_pipe;
nova_syscall_table[NR_shmget] = nova_sys_shmget;
nova_syscall_table[NR_shmat] = nova_sys_shmat;
nova_syscall_table[NR_shmctl] = nova_sys_shmctl;
nova_syscall_table[NR_dup] = nova_sys_dup;
nova_syscall_table[NR_dup2] = nova_sys_dup2;
nova_syscall_table[NR_pause] = nova_sys_pause;
nova_syscall_table[NR_socket] = nova_sys_socket;
nova_syscall_table[NR_accept] = nova_sys_accept;
nova_syscall_table[NR_bind] = nova_sys_bind;
nova_syscall_table[NR_listen] = nova_sys_listen;
nova_syscall_table[NR_socketpair] = nova_sys_socketpair;
nova_syscall_table[NR_setsockopt] = nova_sys_setsockopt;
nova_syscall_table[NR_clone] = nova_sys_clone;
nova_syscall_table[NR_fork] = nova_sys_fork;
nova_syscall_table[NR_vfork] = nova_sys_vfork;
nova_syscall_table[NR_execve] = nova_sys_execve;
nova_syscall_table[NR_exit] = nova_sys_exit;
nova_syscall_table[NR_kill] = nova_sys_kill;
nova_syscall_table[NR_semget] = nova_sys_semget;
nova_syscall_table[NR_semop] = nova_sys_semop;
nova_syscall_table[NR_semctl] = nova_sys_semctl;
nova_syscall_table[NR_shmdt] = nova_sys_shmdt;
nova_syscall_table[NR_msgget] = nova_sys_msgget;
nova_syscall_table[NR_msgsnd] = nova_sys_msgsnd;
nova_syscall_table[NR_msgrcv] = nova_sys_msgrcv;
nova_syscall_table[NR_msgctl] = nova_sys_msgctl;
nova_syscall_table[NR_fcntl] = nova_sys_fcntl;
nova_syscall_table[NR_truncate] = nova_sys_truncate;
nova_syscall_table[NR_ftruncate] = nova_sys_ftruncate;
nova_syscall_table[NR_getdents] = nova_sys_getdents;
nova_syscall_table[NR_getcwd] = nova_sys_getcwd;
nova_syscall_table[NR_chdir] = nova_sys_chdir;
nova_syscall_table[NR_fchdir] = nova_sys_fchdir;
nova_syscall_table[NR_rename] = nova_sys_rename;
nova_syscall_table[NR_mkdir] = nova_sys_mkdir;
nova_syscall_table[NR_rmdir] = nova_sys_rmdir;
nova_syscall_table[NR_creat] = nova_sys_creat;
nova_syscall_table[NR_link] = nova_sys_link;
nova_syscall_table[NR_unlink] = nova_sys_unlink;
nova_syscall_table[NR_symlink] = nova_sys_symlink;
nova_syscall_table[NR_readlink] = nova_sys_readlink;
nova_syscall_table[NR_chmod] = nova_sys_chmod;
nova_syscall_table[NR_fchmod] = nova_sys_fchmod;
nova_syscall_table[NR_chown] = nova_sys_chown;
nova_syscall_table[NR_fchown] = nova_sys_fchown;
nova_syscall_table[NR_lchown] = nova_sys_lchown;
nova_syscall_table[NR_umask] = nova_sys_umask;
nova_syscall_table[NR_sysinfo] = nova_sys_sysinfo;
nova_syscall_table[NR_ptrace] = nova_sys_ptrace;
nova_syscall_table[NR_setuid] = nova_sys_setuid;
nova_syscall_table[NR_setgid] = nova_sys_setgid;
nova_syscall_table[NR_setpgid] = nova_sys_setpgid;
nova_syscall_table[NR_setsid] = nova_sys_setsid;
nova_syscall_table[NR_setreuid] = nova_sys_setreuid;
nova_syscall_table[NR_setregid] = nova_sys_setregid;
nova_syscall_table[NR_setgroups] = nova_sys_setgroups;
nova_syscall_table[NR_setresuid] = nova_sys_setresuid;
nova_syscall_table[NR_setresgid] = nova_sys_setresgid;
nova_syscall_table[NR_setfsuid] = nova_sys_setfsuid;
nova_syscall_table[NR_setfsgid] = nova_sys_setfsgid;
nova_syscall_table[NR_capset] = nova_sys_capset;
nova_syscall_table[NR_utime] = nova_sys_utime;
nova_syscall_table[NR_uselib] = nova_sys_uselib;
nova_syscall_table[NR_personality] = nova_sys_personality;
nova_syscall_table[NR_ustat] = nova_sys_ustat;
nova_syscall_table[NR_statfs] = nova_sys_statfs;
nova_syscall_table[NR_fstatfs] = nova_sys_fstatfs;
nova_syscall_table[NR_sysfs] = nova_sys_sysfs;
nova_syscall_table[NR_getpriority] = nova_sys_getpriority;
nova_syscall_table[NR_setpriority] = nova_sys_setpriority;
nova_syscall_table[NR_sched_setparam] = nova_sys_sched_setparam;
nova_syscall_table[NR_sched_getparam] = nova_sys_sched_getparam;
nova_syscall_table[NR_sched_setscheduler] = nova_sys_sched_setscheduler;
nova_syscall_table[NR_sched_getscheduler] = nova_sys_sched_getscheduler;
nova_syscall_table[NR_sched_get_priority_max] = nova_sys_sched_get_priority_max;
nova_syscall_table[NR_sched_get_priority_min] = nova_sys_sched_get_priority_min;
nova_syscall_table[NR_sched_rr_get_interval] = nova_sys_sched_rr_get_interval;
nova_syscall_table[NR_vhangup] = nova_sys_vhangup;
nova_syscall_table[NR_modify_ldt] = nova_sys_modify_ldt;
nova_syscall_table[NR_pivot_root] = nova_sys_pivot_root;
nova_syscall_table[NR__sysctl] = nova_sys_sysctl;
nova_syscall_table[NR_prctl] = nova_sys_prctl;
nova_syscall_table[NR_adjtimex] = nova_sys_adjtimex;
nova_syscall_table[NR_setrlimit] = nova_sys_setrlimit;
nova_syscall_table[NR_chroot] = nova_sys_chroot;
nova_syscall_table[NR_sync] = nova_sys_sync;
nova_syscall_table[NR_acct] = nova_sys_acct;
nova_syscall_table[NR_settimeofday] = nova_sys_settimeofday;
nova_syscall_table[NR_mount] = nova_sys_mount;
nova_syscall_table[NR_umount2] = nova_sys_umount;
nova_syscall_table[NR_swapon] = nova_sys_swapon;
nova_syscall_table[NR_swapoff] = nova_sys_swapoff;
nova_syscall_table[NR_reboot] = nova_sys_reboot;
nova_syscall_table[NR_sethostname] = nova_sys_sethostname;
nova_syscall_table[NR_setdomainname] = nova_sys_setdomainname;
nova_syscall_table[NR_iopl] = nova_sys_iopl;
nova_syscall_table[NR_ioperm] = nova_sys_ioperm;
nova_syscall_table[NR_init_module] = nova_sys_init_module;
nova_syscall_table[NR_delete_module] = nova_sys_delete_module;
nova_syscall_table[NR_quotactl] = nova_sys_quotactl;
nova_syscall_table[NR_gettid] = nova_sys_gettid;
nova_syscall_table[NR_readahead] = nova_sys_readahead;
nova_syscall_table[NR_setxattr] = nova_sys_setxattr;
nova_syscall_table[NR_lsetxattr] = nova_sys_lsetxattr;
nova_syscall_table[NR_fsetxattr] = nova_sys_fsetxattr;
nova_syscall_table[NR_getxattr] = nova_sys_getxattr;
nova_syscall_table[NR_lgetxattr] = nova_sys_lgetxattr;
nova_syscall_table[NR_fgetxattr] = nova_sys_fgetxattr;
nova_syscall_table[NR_listxattr] = nova_sys_listxattr;
nova_syscall_table[NR_llistxattr] = nova_sys_llistxattr;
nova_syscall_table[NR_flistxattr] = nova_sys_flistxattr;
nova_syscall_table[NR_removexattr] = nova_sys_removexattr;
nova_syscall_table[NR_lremovexattr] = nova_sys_lremovexattr;
nova_syscall_table[NR_fremovexattr] = nova_sys_fremovexattr;
nova_syscall_table[NR_tkill] = nova_sys_tkill;
nova_syscall_table[NR_sched_setaffinity] = nova_sys_sched_setaffinity;
nova_syscall_table[NR_sched_getaffinity] = nova_sys_sched_getaffinity;
nova_syscall_table[NR_set_thread_area] = nova_sys_set_thread_area;
nova_syscall_table[NR_get_thread_area] = nova_sys_get_thread_area;
nova_syscall_table[NR_lookup_dcookie] = nova_sys_lookup_dcookie;
nova_syscall_table[NR_getdents64] = nova_sys_getdents64;
nova_syscall_table[NR_set_tid_address] = nova_sys_set_tid_address;
nova_syscall_table[NR_semtimedop] = nova_sys_semtimedop;
nova_syscall_table[NR_fadvise64] = nova_sys_fadvise64;
nova_syscall_table[NR_utimes] = nova_sys_utimes;
nova_syscall_table[NR_mq_open] = nova_sys_mq_open;
nova_syscall_table[NR_mq_unlink] = nova_sys_mq_unlink;
nova_syscall_table[NR_mq_timedsend] = nova_sys_mq_timedsend;
nova_syscall_table[NR_mq_timedreceive] = nova_sys_mq_timedreceive;
nova_syscall_table[NR_mq_notify] = nova_sys_mq_notify;
nova_syscall_table[NR_mq_getsetattr] = nova_sys_mq_getsetattr;
nova_syscall_table[NR_kexec_load] = nova_sys_kexec_load;
nova_syscall_table[NR_waitid] = nova_sys_waitid;
nova_syscall_table[NR_add_key] = nova_sys_add_key;
nova_syscall_table[NR_request_key] = nova_sys_request_key;
nova_syscall_table[NR_keyctl] = nova_sys_keyctl;
nova_syscall_table[NR_ioprio_set] = nova_sys_ioprio_set;
nova_syscall_table[NR_ioprio_get] = nova_sys_ioprio_get;
nova_syscall_table[NR_inotify_init] = nova_sys_inotify_init;
nova_syscall_table[NR_inotify_add_watch] = nova_sys_inotify_add_watch;
nova_syscall_table[NR_inotify_rm_watch] = nova_sys_inotify_rm_watch;
nova_syscall_table[NR_migrate_pages] = nova_sys_migrate_pages;
nova_syscall_table[NR_openat] = nova_sys_openat;
nova_syscall_table[NR_mkdirat] = nova_sys_mkdirat;
nova_syscall_table[NR_mknodat] = nova_sys_mknodat;
nova_syscall_table[NR_fchownat] = nova_sys_fchownat;
nova_syscall_table[NR_futimesat] = nova_sys_futimesat;
nova_syscall_table[NR_newfstatat] = nova_sys_newfstatat;
nova_syscall_table[NR_unlinkat] = nova_sys_unlinkat;
nova_syscall_table[NR_renameat] = nova_sys_renameat;
nova_syscall_table[NR_linkat] = nova_sys_linkat;
nova_syscall_table[NR_symlinkat] = nova_sys_symlinkat;
nova_syscall_table[NR_readlinkat] = nova_sys_readlinkat;
nova_syscall_table[NR_fchmodat] = nova_sys_fchmodat;
nova_syscall_table[NR_faccessat] = nova_sys_faccessat;
nova_syscall_table[NR_pselect6] = nova_sys_pselect6;
nova_syscall_table[NR_unshare] = nova_sys_unshare;
nova_syscall_table[NR_set_robust_list] = nova_sys_set_robust_list;
nova_syscall_table[NR_get_robust_list] = nova_sys_get_robust_list;
nova_syscall_table[NR_utimensat] = nova_sys_utimensat;
nova_syscall_table[NR_eventfd] = nova_sys_eventfd;
nova_syscall_table[NR_fallocate] = nova_sys_fallocate;
nova_syscall_table[NR_timerfd_settime] = nova_sys_timerfd_settime;
nova_syscall_table[NR_timerfd_gettime] = nova_sys_timerfd_gettime;
nova_syscall_table[NR_accept4] = nova_sys_accept4;
nova_syscall_table[NR_eventfd2] = nova_sys_eventfd2;
nova_syscall_table[NR_dup3] = nova_sys_dup3;
nova_syscall_table[NR_pipe2] = nova_sys_pipe2;
nova_syscall_table[NR_inotify_init1] = nova_sys_inotify_init1;
nova_syscall_table[NR_perf_event_open] = nova_sys_perf_event_open;
nova_syscall_table[NR_fanotify_init] = nova_sys_fanotify_init;
nova_syscall_table[NR_fanotify_mark] = nova_sys_fanotify_mark;
nova_syscall_table[NR_prlimit64] = nova_sys_prlimit64;
nova_syscall_table[NR_name_to_handle_at] = nova_sys_name_to_handle_at;
nova_syscall_table[NR_open_by_handle_at] = nova_sys_open_by_handle_at;
nova_syscall_table[NR_clock_adjtime] = nova_sys_clock_adjtime;
nova_syscall_table[NR_syncfs] = nova_sys_syncfs;
nova_syscall_table[NR_setns] = nova_sys_setns;
nova_syscall_table[NR_getcpu] = nova_sys_getcpu;
nova_syscall_table[NR_process_vm_readv] = nova_sys_process_vm_readv;
nova_syscall_table[NR_process_vm_writev] = nova_sys_process_vm_writev;
nova_syscall_table[NR_kcmp] = nova_sys_kcmp;
nova_syscall_table[NR_finit_module] = nova_sys_finit_module;


int nova_handled_syscals[] = {
	 NR_open,
	NR_stat,
	NR_fstat,
	NR_lstat,
	NR_access,
	NR_pipe,
	NR_shmget,
	NR_shmat,
	NR_shmctl,
	NR_dup,
	NR_dup2,
	NR_pause,
	NR_socket,
	NR_accept,
	NR_bind,
	NR_listen,
	NR_socketpair,
	NR_setsockopt,
	NR_clone,
	NR_fork,
	NR_vfork,
	NR_execve,
	NR_exit,
	NR_kill,
	NR_semget,
	NR_semop,
	NR_semctl,
	NR_shmdt,
	NR_msgget,
	NR_msgsnd,
	NR_msgrcv,
	NR_msgctl,
	NR_fcntl,
	NR_truncate,
	NR_ftruncate,
	NR_getdents,
	NR_getcwd,
	NR_chdir,
	NR_fchdir,
	NR_rename,
	NR_mkdir,
	NR_rmdir,
	NR_creat,
	NR_link,
	NR_unlink,
	NR_symlink,
	NR_readlink,
	NR_chmod,
	NR_fchmod,
	NR_chown,
	NR_fchown,
	NR_lchown,
	NR_umask,
	NR_sysinfo,
	NR_ptrace,
	NR_setuid,
	NR_setgid,
	NR_setpgid,
	NR_setsid,
	NR_setreuid,
	NR_setregid,
	NR_setgroups,
	NR_setresuid,
	NR_setresgid,
	NR_setfsuid,
	NR_setfsgid,
	NR_capset,
	NR_utime,
	NR_uselib,
	NR_personality,
	NR_ustat,
	NR_statfs,
	NR_fstatfs,
	NR_sysfs,
	NR_getpriority,
	NR_setpriority,
	NR_sched_setparam,
	NR_sched_getparam,
	NR_sched_setscheduler,
	NR_sched_getscheduler,
	NR_sched_get_priority_max,
	NR_sched_get_priority_min,
	NR_sched_rr_get_interval,
	NR_vhangup,
	NR_modify_ldt,
	NR_pivot_root,
	NR__sysctl,
	NR_prctl,
	NR_adjtimex,
	NR_setrlimit,
	NR_chroot,
	NR_sync,
	NR_acct,
	NR_settimeofday,
	NR_mount,
	NR_umount2,
	NR_swapon,
	NR_swapoff,
	NR_reboot,
	NR_sethostname,
	NR_setdomainname,
	NR_iopl,
	NR_ioperm,
	NR_init_module,
	NR_delete_module,
	NR_quotactl,
	NR_gettid,
	NR_readahead,
	NR_setxattr,
	NR_lsetxattr,
	NR_fsetxattr,
	NR_getxattr,
	NR_lgetxattr,
	NR_fgetxattr,
	NR_listxattr,
	NR_llistxattr,
	NR_flistxattr,
	NR_removexattr,
	NR_lremovexattr,
	NR_fremovexattr,
	NR_tkill,
	NR_sched_setaffinity,
	NR_sched_getaffinity,
	NR_set_thread_area,
	NR_get_thread_area,
	NR_lookup_dcookie,
	NR_getdents64,
	NR_set_tid_address,
	NR_semtimedop,
	NR_fadvise64,
	NR_utimes,
	NR_mq_open,
	NR_mq_unlink,
	NR_mq_timedsend,
	NR_mq_timedreceive,
	NR_mq_notify,
	NR_mq_getsetattr,
	NR_kexec_load,
	NR_waitid,
	NR_add_key,
	NR_request_key,
	NR_keyctl,
	NR_ioprio_set,
	NR_ioprio_get,
	NR_inotify_init,
	NR_inotify_add_watch,
	NR_inotify_rm_watch,
	NR_migrate_pages,
	NR_openat,
	NR_mkdirat,
	NR_mknodat,
	NR_fchownat,
	NR_futimesat,
	NR_newfstatat,
	NR_unlinkat,
	NR_renameat,
	NR_linkat,
	NR_symlinkat,
	NR_readlinkat,
	NR_fchmodat,
	NR_faccessat,
	NR_pselect6,
	NR_unshare,
	NR_set_robust_list,
	NR_get_robust_list,
	NR_utimensat,
	NR_eventfd,
	NR_fallocate,
	NR_timerfd_settime,
	NR_timerfd_gettime,
	NR_accept4,
	NR_eventfd2,
	NR_dup3,
	NR_pipe2,
	NR_inotify_init1,
	NR_perf_event_open,
	NR_fanotify_init,
	NR_fanotify_mark,
	NR_prlimit64,
	NR_name_to_handle_at,
	NR_open_by_handle_at,
	NR_clock_adjtime,
	NR_syncfs,
	NR_setns,
	NR_getcpu,
	NR_process_vm_readv,
	NR_process_vm_writev,
	NR_kcmp,
	NR_finit_module
};

