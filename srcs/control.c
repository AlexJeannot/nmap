#include "../incs/nmap.h"

int8_t isHostUp(const t_env *env) {
    return (env->ping.imcp_r || env->ping.tcp_r);
}