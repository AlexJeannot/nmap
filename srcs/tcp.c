#include "../incs/nmap.h"

void setHeader_TCP(t_env *env, struct tcphdr *header, uint16_t port)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->l_target->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_TCP;
    chk.length = htons((uint16_t)sizeof(struct tcphdr));

    bzero(header, sizeof(struct tcphdr));
    header->th_sport = htons(44380);
    header->th_dport = htons(port);
    header->th_seq = 0; // TODO
    header->th_ack = 0;
    header->th_off = 5;
    header->th_win =  htons(1024);
    header->th_urp = 0;

    switch (env->scan.current) {
        case (SSYN):   header->th_flags = TH_SYN;                      break;
        case (SPING):   header->th_flags = TH_SYN;                      break;
        case (SACK):            header->th_flags = TH_ACK;                      break;
        case (SNULL):           header->th_flags = 0;                           break;
        case (SFIN):            header->th_flags = TH_FIN;                      break;
        case (SXMAS):           header->th_flags = TH_FIN | TH_PUSH | TH_URG;   break;
    }

    memcpy(&chk.hdr.tcp, header, sizeof(struct tcphdr));
    header->th_sum = calcul_checksum(&chk, sizeof(struct tcphdr) + CHKSM_PREHDR_LEN);
}

void sendSegment(t_env *env)
{
    struct tcphdr tcp_header;

    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setHeader_TCP(env, &tcp_header, env->port.list[pos]);
        setTargetPort(&env->l_target->n_ip, env->port.list[pos]);

        if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
            errorMsgExit("sendto() call", "TCP scan");
    }
}