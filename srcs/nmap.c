#include "../incs/nmap.h"




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
    struct icmp icmp_header;
    struct tcphdr  tcp_header;
    t_probe_info    info;

    setHeader_ICMP(&icmp_header);

    setProbeInfo(env, &info, SSYN);
    setProbePort(&info, 80);
    setHeader_TCP(&tcp_header, &info);
    // setTargetPort(env, 80);

    env->scan.current = SPING;
    if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
        errorMsgExit("sniffer thread creation", "ping");

    env->ping.ts_start = get_ts_ms();
    if (sendto(env->sock.icmp, &icmp_header, sizeof(struct icmp), 0, &info.target, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "ICMP ping");

    if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &info.target, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "TCP ping");

    alarm(1);
    pthread_join(env->sniffer_id, NULL);
    return ((isHostUp(env)) ? displayHostUp(env) : displayHostDown(env));
}


void scanTarget(t_env *env)
{
    for (uint8_t type = 1; type <= SUDP ; type <<= 1) {
        if (env->scan.all & type) {
            printf("\n-------------------------\n");
            env->scan.current = type;
            if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
                errorMsgExit("sniffer thread creation", "TCP scan");
            
            (type == SUDP) ? sendAllDatagram(env) : sendAllSegment(env, type);
            alarm(1);
            pthread_join(env->sniffer_id, NULL);
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
    createSocket(&env);

    while (env.l_target) {
        if (pingTarget(&env)) {
            printf("\n############################# SCAN #############################\n");
            scanTarget(&env);
            displayResults(&env);
        }
        env.l_target = env.l_target->next;
    }
    return (0);
}