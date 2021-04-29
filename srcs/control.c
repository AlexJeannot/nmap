#include "../incs/nmap.h"

/*
**  Return TRUE if host has reply on ICMP request or TCP syn packet
*/
int8_t isHostUp(const t_env *env) {
    return (env->ping.imcp_r || env->ping.tcp_r);
}

/*
**  Return index of port if it is in port range
*/
int16_t  isPortFromScan(const t_env *env, uint16_t port)
{
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] == port)
            return (pos);
    }
    return (-1);
}

/*
**  Return TRUE if ICMP reply host unreachable (type 3 && code 1/2/3/9/10/13)
*/
int8_t  isHostUnreachable(struct icmp *icmp_hdr)
{
    u_char  type;
    u_char  code;

    type = icmp_hdr->icmp_type;
    code = icmp_hdr->icmp_code;
    if (type == 3 || code == 1 || code == 2 || code == 3
        || code == 9 || code == 10 || code == 13)
        return (TRUE);
    return (FALSE);
}

/*
**  Return TRUE if host has already been provided
*/
uint8_t isHostDuplicate(t_env *env, struct hostent *host)
{
    t_list_target *tmp;
    int ret;

    tmp = env->target.list;
    while (tmp) {
        if ((ret = memcmp(&tmp->ip, host->h_addr, sizeof(in_addr_t))) == 0)
            return (TRUE);
        tmp = tmp->next;
    }
    return (FALSE);
}

/*
**  Return TRUE if argument is an option (must start by '--')
*/
int8_t isOption(t_env *env, char *arg)
{
    if (strlen(arg) < 4 || arg[0] != '-' || arg[1] != '-') {
        printf("ft_nmap: invalid argument: %s\n", arg);
        displayHelp(env, 1);
    }
    return (TRUE);
}