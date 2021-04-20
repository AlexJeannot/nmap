#include "../incs/nmap.h"

void createSocket(t_env *env)
{
    if ((env->sock.icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        errorMsgExit("ICMP socket", "socket() call failed");
    if ((env->sock.tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        errorMsgExit("TCP socket", "socket() call failed");

    if (env->scan.all & SUDP) {
        if ((env->sock.udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
            errorMsgExit("UDP socket", "socket() call failed");
    }
}   

void setTargetPort(struct sockaddr *target, uint16_t port)
{
    ((struct sockaddr_in *)target)->sin_port = htons(port);
}

void getSourceIP(t_env *env)
{
    struct ifaddrs      *intf;
    struct sockaddr_in  *addr;
    char                ip[INET_ADDRSTRLEN];

    if (getifaddrs(&intf) == -1)
        errorMsgExit("interface", "cannot get machine interface(s)");
    for (struct ifaddrs *tmp = intf; tmp != NULL; tmp = tmp->ifa_next) {
        addr = (struct sockaddr_in *)tmp->ifa_addr;
        if (addr->sin_family == AF_INET) {
            bzero(&ip, INET_ADDRSTRLEN);
            if (inet_ntop(AF_INET, &addr->sin_addr, &ip[0], INET_ADDRSTRLEN)) {
                if (strncmp(&ip[0], "127", 3)) {
                    strncpy(&env->intf.s_ip[0], &ip[0], INET_ADDRSTRLEN);
                    memcpy(&env->intf.n_ip, &addr->sin_addr, sizeof(in_addr_t));
                    return ;
                }
            }
        }
    }
    freeifaddrs(intf);
}

void setProbeInfo(t_env *env, t_probe_info *info, uint8_t type)
{
    bzero(info, sizeof(t_probe_info));
    memcpy(&info->intf_ip, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&info->target, &env->l_target->n_ip, sizeof(struct sockaddr));
    memcpy(&info->type, &type, sizeof(uint8_t));

    if (type == SUDP)
        memcpy(&info->sock, &env->sock.udp, sizeof(int32_t));
    else
        memcpy(&info->sock, &env->sock.tcp, sizeof(int32_t));
}

void setProbePort(t_probe_info *info, uint16_t port)
{
    memcpy(&info->port, &port, sizeof(uint16_t));
    ((struct sockaddr_in *)&info->target)->sin_port = htons(port);
}

uint16_t getMinPort(const t_env *env)
{
    uint16_t    min;

    min = 65535;
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] < min)
            min = env->port.list[pos];
    }
    return (min);
}

uint16_t getMaxPort(const t_env *env)
{
    uint16_t    max;

    max = 1;
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] > max)
            max = env->port.list[pos];
    }
    return (max);
}

int8_t getPortIndex(t_env *env)
{
    uint8_t res;

    pthread_mutex_lock(&env->port.lock);
    res = (env->port.index < env->port.nb) ? TRUE : FALSE;
    pthread_mutex_unlock(&env->port.lock);
    return (res);
}

int16_t setPortIndex(t_env *env)
{
    int16_t res;

    pthread_mutex_lock(&env->port.lock);
    res = (env->port.index < env->port.nb) ? env->port.index : -1;
    env->port.index++;
    pthread_mutex_unlock(&env->port.lock);
    return (res);
}

/*
 * Checksum calculation
 * data is adress of first header byte
 * For every 2 bytes of header 
 * -> Add 2 bytes value to checksum
 * If header length is odd
 * -> Add last byte value to checksum
 * Add most significant byte and least significant byte
 * ones complement of checksum
*/ 
uint16_t	calcul_checksum(void *data, int32_t size)
{
	uint64_t	checksum;
	uint16_t	*addr;

	checksum = 0;
	addr = data;
	while (size > 1)
	{
		checksum += *addr;
		addr++;
		size -= (int)sizeof(uint16_t);
	}
	if (size == 1)
		checksum += *(uint8_t*)addr;
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);
	checksum = ~checksum;

	return ((uint16_t)checksum);
}