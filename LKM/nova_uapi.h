#ifndef __LKM_NOVA_UAPI_H__
#define __LKM_NOVA_UAPI_H__

#define LKM_INTERFACE_FILE_PROC "hello"

enum nova_u2l_order {
    NOVA_U2L_NOOP,
    NOVA_U2L_ENABLE,
    NOVA_U2L_DISABLE,
    NOVA_U2L_SET_PID
};

struct nova_user2lkm {
    enum nova_u2l_order order;
    pid_t pid;
};
#endif
