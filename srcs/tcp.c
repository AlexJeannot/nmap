#include "../incs/nmap.h"

void setHeader_TCP(const t_env *env, struct tcphdr *header, uint16_t port)
{
    t_tcp_checksum chk;

    bzero(&chk, sizeof(t_tcp_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->l_target->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_TCP;
    chk.length = htons((uint16_t)sizeof(struct tcphdr));

    bzero(header, sizeof(struct tcphdr));
    header->th_sport = htons(44380);
    header->th_dport = htons(port);
    header->th_seq = 0;
    header->th_ack = 0;
    header->th_off = 5;
    header->th_flags = TH_SYN;
    header->th_win =  htons(1024);
    header->th_urp = 0;

    memcpy(&chk.tcp, header, sizeof(struct tcphdr));
    header->th_sum = calcul_checksum(&chk, sizeof(t_tcp_checksum));
}