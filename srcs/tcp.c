#include "../incs/nmap.h"

/*
**  Handle TCP reply
**  If port is not from port range then stop here
**  Set port state depending on current scan type
*/
void handleResponse_TCP(t_env *env, struct tcphdr *hdr)
{
    int16_t        index;

    if ((index = isPortFromScan(env, ntohs(hdr->th_sport))) == -1 || ntohs(hdr->th_dport) != 44380)
        return ;

    if ((hdr->th_flags & TH_SYN) && (hdr->th_flags & TH_ACK)) {
        if (env->scan.current == SSYN)
            env->port.result[index].syn = OPEN;
    }
    else if ((hdr->th_flags & TH_RST)) {
        switch (env->scan.current) {
            case (SSYN):    env->port.result[index].syn = CLOSED;   break;
            case (SACK):    env->port.result[index].ack = UNFILT;   break;
            case (SFIN):    env->port.result[index].fin = CLOSED;   break;
            case (SNULL):   env->port.result[index].null = CLOSED;  break;
            case (SXMAS):   env->port.result[index].xmas = CLOSED;  break;
        }
    }
}

/*
**  Set TCP header values
**  For checksum need to add a preheader (see t_checksum structure in header file incs/nmap.h)
*/
void setHeader_TCP(t_env *env, struct tcphdr *hdr, uint16_t port)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->target.list->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_TCP;
    chk.length = htons((uint16_t)sizeof(struct tcphdr));

    bzero(hdr, sizeof(struct tcphdr));
    hdr->th_sport = htons(44380);
    hdr->th_dport = htons(port);
    hdr->th_seq = 0;
    hdr->th_ack = 0;
    hdr->th_off = 5;
    hdr->th_win =  htons(1024);
    hdr->th_urp = 0;

    switch (env->scan.current) {
        case (SSYN):    hdr->th_flags = TH_SYN;                      break;
        case (SPING):   hdr->th_flags = TH_SYN;                      break;
        case (SACK):    hdr->th_flags = TH_ACK;                      break;
        case (SNULL):   hdr->th_flags = 0;                           break;
        case (SFIN):    hdr->th_flags = TH_FIN;                      break;
        case (SXMAS):   hdr->th_flags = TH_FIN | TH_PUSH | TH_URG;   break;
    }

    memcpy(&chk.hdr.tcp, hdr, sizeof(struct tcphdr));
    hdr->th_sum = calcul_checksum(&chk, sizeof(struct tcphdr) + CHKSM_PREHDR_LEN);
}

/*
**  Send segment
**  For each port in list
**  -- Set header values
**  -- Set target port
**  -- Sent segment to target
*/
void sendSegment(t_env *env)
{
    struct tcphdr hdr;

    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setHeader_TCP(env, &hdr, env->port.list[pos]);
        setTargetPort(&env->target.list->n_ip, env->port.list[pos]);
        if (sendto(env->sock.tcp, &hdr, sizeof(struct tcphdr), 0, &env->target.list->n_ip, sizeof(struct sockaddr)) < 0)
            errorMsgExit(env, "sendto() call", "TCP scan");
    }
}