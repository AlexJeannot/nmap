#include "../incs/nmap.h"

/*
**  Handle ping reply
**  Verify if it is an IMCP or TCP packet
**  No need to do futher verification because filter has already been apply before (see sniffer.c file / setFilter() function)
*/
void    handleResponse_ping(t_env *env, struct ip *hdr)
{
    if (hdr->ip_p == IPPROTO_ICMP || hdr->ip_p == IPPROTO_TCP) {
        switch (hdr->ip_p) {
            case (IPPROTO_ICMP):    env->ping.imcp_r = 1;   break;
            case (IPPROTO_TCP):    env->ping.tcp_r = 1;     break;
        }
    }
    else 
        return ;
}

/*
**  Function in charge of pinging (first scan step)
**  Set current sacn type as PING
**  Set values for IMCP and TCP SYN 80 packet
**  Set sniffer state as not ready and not finished
**  Create sniffer thread
**  Wait for sniffer thread to be ready
**  Send ICMP and TCP packets
**  Wait for sniffer thread to finish (timeout is set as 1000ms in pcap_open_live())
**  Display if host is up or down and return TRUE/FALSE accordingly
*/
int8_t  pingTarget(t_env *env)
{
    struct icmp     icmp_hdr;
    struct tcphdr   tcp_hdr;

    env->scan.current = SPING;
    setHeader_ICMP(&icmp_hdr);
    setHeader_TCP(env, &tcp_hdr, 80);
    setTargetPort(&env->target.list->n_ip, 80);
    setSnifferState(env, &env->sniffer.ready, FALSE);
    setSnifferState(env, &env->sniffer.end, FALSE);

    if (pthread_create(&env->sniffer.id, NULL, packetSniffer, (void *)env))
        errorMsgExit(env, "sniffer thread creation", "ping");
    waitForSniffer(env);

    if (sendto(env->sock.icmp, &icmp_hdr, sizeof(struct icmp), 0, &env->target.list->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit(env, "sendto() call", "ICMP ping");
    if (sendto(env->sock.tcp, &tcp_hdr, sizeof(struct tcphdr), 0, &env->target.list->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit(env, "sendto() call", "TCP ping");

    waitForPing(env);
    return ((isHostUp(env)) ? displayHostUp(env) : displayHostDown(env));
}