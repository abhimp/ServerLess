#ifndef __LKM_NOVA_INTERFACE_H__
#define __LKM_NOVA_INTERFACE_H__

//Dirty hack
static int configureSyscallRedirection(void);
static void restorSyscallRedirection(void);

static inline size_t novaIsoSetParam(const char *buf, size_t count) {
    struct nova_user2lkm *myorder;
    myorder = (struct nova_user2lkm *)buf;
    switch(myorder->order) {
    case NOVA_U2L_LKM_STATUS:
        {
            int status;
            if(myorder->len != sizeof(int32_t))
                return -EINVAL;
            status = *((int32_t*) myorder->value);
            if(status)
                configureSyscallRedirection();
            else
                restorSyscallRedirection();
        }
        break;
    case NOVA_U2L_NOVA_ID:
        {
            novaSetNovaId(myorder->nova_id);
            printk(KERN_ALERT "Added nova filter for nid %d\n", myorder->nova_id);
        }
        break;
    case NOVA_U2L_MONITOR_PID:
        {
            novaSetMonitorPid(myorder->monitor_pid);
            printk(KERN_ALERT "Added nova monitor pid %d\n", myorder->monitor_pid);
        }
        break;
    case NOVA_U2L_NOVA_ID_N_MONITOR_PID:
        {
            novaSetNovaId(myorder->nova_id);
            novaSetMonitorPid(myorder->monitor_pid);
            printk(KERN_ALERT "Added nova filter for nid %d\n", myorder->nova_id);
            printk(KERN_ALERT "Added nova monitor pid %d\n", myorder->monitor_pid);
        }
        break;
    case NOVA_U2L_NOVA_HOME:
        {
            char *path;
            int ret;
            printk(KERN_ALERT "Nova Set Home: %zu %zu %zu\n", count, sizeof(struct nova_user2lkm), myorder->len);
            if(myorder->len == 0 || count < (sizeof(struct nova_user2lkm) + myorder->len))
                return -EINVAL;
            if(myorder->len > PATH_MAX)
                return -ENAMETOOLONG;
            path = myorder->value;
            if(path[0] != '/' || path[myorder->len - 1] != 0) //path have to be a absolute path and null terminated
                return -EINVAL;
            if((ret = novaSetHomePath(path, myorder->len)) < 0)
                return ret;
        }
        break;
    default:
        return -EINVAL;
    }
    return count;
}


#endif //__LKM_NOVA_INTERFACE_H__
