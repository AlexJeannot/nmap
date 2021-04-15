#include "../incs/nmap.h"




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

uint8_t waitForResponse(t_env *env, uint16_t ms)
{
    struct timeval start;
    struct timeval check;
    struct timezone tz;

    bzero(&start, sizeof(start));
    bzero(&check, sizeof(check));

    gettimeofday(&start, &tz);
    while ((!(env->ping.imcp_r) && !(env->ping.tcp_r)) || ((check.tv_sec * 1000) - (start.tv_sec * 1000)) < ms) {
        // printf("((check.tv_sec * 1000) - (start.tv_sec * 1000)) = %ld\n", ((check.tv_sec * 1000) - (start.tv_sec * 1000)));
        gettimeofday(&check, &tz);
    }
    if (((check.tv_sec * 1000) - (start.tv_sec * 1000)) < ms) {
        return (FALSE);
    }
    return (TRUE);
}

int8_t displayHostUp(const t_env *env)
{
    printf("Host: %s [%s] is up (%LF ms)\n", env->l_target->s_ip, env->l_target->s_host, (env->ping.ts_end - env->ping.ts_start));
    return (1);
}

int8_t displayHostDown(const t_env *env)
{
    printf("Host: %s [%s] seems down\n", env->l_target->s_ip, env->l_target->s_host);
    return (0);
}

int8_t isHostUp(const t_env *env) {
    printf("env->ping.imcp_r = %d\n", env->ping.imcp_r);
    printf("env->ping.tcp_r = %d\n", env->ping.tcp_r);
    return (env->ping.imcp_r || env->ping.tcp_r);
}

/*
 * Get time is millisecond
*/
long double	get_ts_ms(void)
{
	struct	timeval tv;
	struct	timezone tz;

	gettimeofday(&tv, &tz);
	return (((long double)tv.tv_sec * 1000) + ((long double)tv.tv_usec / 1000));
}

int8_t pingTarget(t_env *env)
{
    /* ---------- SOCKET CREATION -------------- */
    int sock_icmp, sock_tcp;
    if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        errorMsgExit("ICMP socket", "ping socket() call failed");
    if ((sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        errorMsgExit("TCP socket", "ping socket() call failed");

    /* ---------- PACKET CREATION -------------- */
    struct icmp icmp_p;
    struct tcphdr  tcp_p;
    bzero(&icmp_p, sizeof(struct icmp));
    bzero(&tcp_p, sizeof(struct tcphdr));

    icmp_p.icmp_type = 8;
    icmp_p.icmp_code = 0;
    icmp_p.icmp_hun.ih_idseq.icd_id = 42;
    icmp_p.icmp_cksum = calcul_checksum(&icmp_p, sizeof(struct icmp));

    tcp_p.th_sport = htons(44444);
    tcp_p.th_dport = htons(80);
    tcp_p.th_seq = 0;
    tcp_p.th_ack = 0;
    tcp_p.th_off = 5;
    tcp_p.th_flags = TH_SYN;
    tcp_p.th_win =  htons(1024);
    tcp_p.th_sum = 120;
    tcp_p.th_urp = 0;


    /* ---------- TARGET CREATION -------------- */
    struct sockaddr_in sender;
    bzero(&sender, sizeof(sender));
    
    sender.sin_family = AF_INET;
    sender.sin_port = htons(80);
    memcpy(&sender.sin_addr, &env->l_target->ip, sizeof(struct in_addr));

    env->s_type = S_PING;
    if (pthread_create(&env->ping.id, NULL, packetSniffer, (void *)env))
        errorMsgExit("thread creation", "ping");


    // packetSniffer(env, S_PING);

    /* ---------- SENDTO CALL -------------- */

    env->ping.ts_start = get_ts_ms();
    if (sendto(sock_icmp, &icmp_p, sizeof(struct icmp), 0, (struct sockaddr *)&sender, sizeof(struct sockaddr)) < 0) {
        perror("SENDTO ICMP");
    }

    if (sendto(sock_tcp, &tcp_p, sizeof(struct tcphdr), 0, (struct sockaddr *)&sender, sizeof(struct sockaddr)) < 0) {
        perror("SENDTO TCP");
    }

    alarm(1);
    pthread_join(env->ping.id, NULL);
    return ((isHostUp(env)) ? displayHostUp(env) : displayHostDown(env));
}

void scanTarget(t_env *env)
{
    /* ---------- SOCKET CREATION -------------- */
    int sock_tcp;
    if ((sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        errorMsgExit("TCP socket", "ping socket() call failed");

    char addr_ip1[INET_ADDRSTRLEN];
    bzero(&addr_ip1, INET_ADDRSTRLEN);
    printf("AVANT inet_ntop SENDER\n");
    inet_ntop(AF_INET, &env->l_target->ip, &addr_ip1[0], INET_ADDRSTRLEN);

    printf("AVANT printf SENDER\n");
    printf("IP = %s\n", addr_ip1);

    /* ---------- PACKET CREATION -------------- */
    struct tcphdr tcp_header;
    setHeader_TCP(env, &tcp_header, 80);

    /* ---------- TARGET CREATION -------------- */
    struct sockaddr_in sender;
    bzero(&sender, sizeof(sender));
    printf("AVANT BZERO SENDER\n");
    
    sender.sin_family = AF_INET;
    sender.sin_port = htons(80);
    printf("AVANT MEMCPY SENDER\n");
    char addr_ip[INET_ADDRSTRLEN];
    bzero(&addr_ip, INET_ADDRSTRLEN);
    printf("AVANT inet_ntop SENDER\n");
    inet_ntop(AF_INET, &env->l_target->ip, &addr_ip[0], INET_ADDRSTRLEN);

    printf("AVANT printf SENDER\n");
    printf("IP = %s\n", addr_ip);
    memcpy(&sender.sin_addr, &env->l_target->ip, sizeof(struct in_addr));
    printf("APRES MEMCPY SENDER\n");

    long double bef;
    long double after;

    bef = get_ts_ms();
    printf("AVANT BOUCLE SEND\n");
    for (uint16_t count = 0; count < env->nb_port; count++) {
        if (sendto(sock_tcp, &tcp_header, sizeof(struct tcphdr), 0, (struct sockaddr *)&sender, sizeof(struct sockaddr)) < 0) {
            perror("SENDTO TCP");
        }
        if (count % 100 == 0)
            usleep(100000);
    }
    printf("APRES BOUCLE SEND\n");
    after = get_ts_ms();

    printf("time = %LF\n", (after - bef));
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
}

int main(int argc, char **argv)
{
    t_env env;

    bzero(&env, sizeof(env));
    bzero(&siginfo, sizeof(siginfo));
    parseArgs(&env, argc, argv);
    getSourceIP(&env);

    while (env.l_target) {
        if (pingTarget(&env)) {
            scanTarget(&env);
        }
        env.l_target = env.l_target->next;
    }
    return (0);
}