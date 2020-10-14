#ifndef __LKM_NOVA_UAPI_H__
#define __LKM_NOVA_UAPI_H__

#define LKM_INTERFACE_FILE_PROC "hello"
typedef gid_t nova_id_t;

enum nova_u2l_order {
    NOVA_U2L_NOOP,
    NOVA_U2L_LKM_STATUS,
    NOVA_U2L_NOVA_ID,
    NOVA_U2L_MONITOR_PID,
    NOVA_U2L_NOVA_HOME,
    NOVA_U2L_NOVA_ID_N_MONITOR_PID,
};


struct nova_user2lkm {
    enum nova_u2l_order order;
    size_t len; // total length of value
    nova_id_t nova_id;
    pid_t monitor_pid;
    char value[0]; //single value or multiple
};

#endif
