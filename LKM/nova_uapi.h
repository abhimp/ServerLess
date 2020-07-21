#ifndef __LKM_NOVA_UAPI_H__
#define __LKM_NOVA_UAPI_H__

#define LKM_INTERFACE_FILE_PROC "hello"
typedef gid_t nova_id_t;

enum nova_u2l_order {
    NOVA_U2L_NOOP,
    NOVA_U2L_ENABLE,
    NOVA_U2L_DISABLE,
    NOVA_U2L_SET_NOVA_ID,
    NOVA_U2L_SET_MONITOR_PID,
    NOVA_U2L_SET_NOVA_ID_N_MONITOR_PID
};

struct nova_user2lkm {
    enum nova_u2l_order order;
    nova_id_t nova_id;
    pid_t monitor_pid;
};
#endif
