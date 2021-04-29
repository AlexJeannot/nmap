#include "../incs/nmap.h"

/*
**  Create socket for network communication
**  ICMP for ping purpose
**  TCP for ping and scan purpose
**  UDP for scan purpose (if UDP scan type requested)
*/
void createSocket(t_env *env)
{
    if ((env->sock.icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        errorMsgExit(env, "ICMP socket", "socket() call failed");
    if ((env->sock.tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        errorMsgExit(env, "TCP socket", "socket() call failed");

    if (env->scan.all & SUDP) {
        if ((env->sock.udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
            errorMsgExit(env, "UDP socket", "socket() call failed");
    }
}   

/*
**  Set target port in sockaddr structure before sendto()
*/
void setTargetPort(struct sockaddr *target, uint16_t port)
{
    ((struct sockaddr_in *)target)->sin_port = htons(port);
}

/*
**  Get source IP for IP packet production
**  Get all interfaces
**  If AF_INET
**  -- If not localhost
**  --- Copy adress in env structure
**  Free interfaces list
*/
void getSourceIP(t_env *env)
{
    struct ifaddrs      *intf;
    struct sockaddr_in  *addr;
    char                ip[INET_ADDRSTRLEN];

    if (getifaddrs(&intf) == -1)
        errorMsgExit(env, "interface", "cannot get machine interface(s)");
    for (struct ifaddrs *tmp = intf; tmp != NULL; tmp = tmp->ifa_next) {
        addr = (struct sockaddr_in *)tmp->ifa_addr;
        if (addr->sin_family == AF_INET) {
            bzero(&ip, INET_ADDRSTRLEN);
            if (inet_ntop(AF_INET, &addr->sin_addr, &ip[0], INET_ADDRSTRLEN)) {
                if (strncmp(&ip[0], "127", 3)) {
                    strncpy(&env->intf.s_ip[0], &ip[0], INET_ADDRSTRLEN);
                    memcpy(&env->intf.n_ip, &addr->sin_addr, sizeof(in_addr_t));
                    freeifaddrs(intf);
                    return ;
                }
            }
        }
    }
    freeifaddrs(intf);
}

/*
**  Get offset of packet that cause an ICMP reply
**  Add Ethernet frame header length
**  Add IP header length + ICMP header length
**  Add IP header length
*/
uint16_t getEncapDataOffset(const u_char *packet)
{
    struct ip   *ip_hdr;
    uint16_t    offset;

    offset = ETHHDR_LEN;
    ip_hdr = (struct ip *)&packet[offset];
    offset += (ip_hdr->ip_hl * 4) + ICMP_MINLEN;
    ip_hdr = (struct ip *)&packet[offset];
    offset += (ip_hdr->ip_hl * 4);
    return (offset);
}

/*
**  Get min port of target port range
*/
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

/*
**  Get max port of target port range
*/
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