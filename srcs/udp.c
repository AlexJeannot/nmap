#include "../incs/nmap.h"

/*
**  Handle UDP reply
**  If port is not from port range then stop here
**  Set port state on OPEN
*/
void handleReponse_UDP(t_env *env, struct udphdr *hdr)
{
    int16_t index;

    if ((index = isPortFromScan(env, ntohs(hdr->uh_sport))) == -1 || ntohs(hdr->uh_dport) != 44380)
        return ;
    env->port.result[index].udp = OPEN;
}

/*
**  Set UDP header values
**  For checksum need to add a preheader (see t_checksum structure in header file incs/nmap.h)
*/
void setHeader_UDP(t_env *env, struct udphdr *hdr, uint16_t port)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->target.list->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_UDP;
    chk.length = htons((uint16_t)sizeof(struct udphdr)+ 14);

    bzero(hdr, sizeof(struct udphdr));
    hdr->uh_dport = htons(port);
    hdr->uh_sport = htons(44380);
    hdr->uh_ulen = htons(22);

    memcpy(&chk.hdr.udp, hdr, sizeof(struct udphdr));
    hdr->uh_sum = calcul_checksum(&chk, sizeof(struct udphdr) + CHKSM_PREHDR_LEN);
}

/*
**  Send datagram
**  For each port in list
**  -- Set header values
**  -- Set target port
**  -- Sent segment to target
**  -- Wait 1000ms accordingly to RFC IMCP reply timing
*/
void sendDatagram(t_env *env)
{
    struct udphdr udp_hdr;
    char data[22];
    
    bzero(&data[0], 22);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setTargetPort(&env->target.list->n_ip, env->port.list[pos]);
        setHeader_UDP(env, &udp_hdr, env->port.list[pos]);
        memcpy(&data[0], &udp_hdr, sizeof(struct udphdr));
        if (sendto(env->sock.udp, &data, 22, 0, &env->target.list->n_ip, sizeof(struct sockaddr)) < 0)
            errorMsgExit(env, "sendto() call", "UDP scan");
        usleep(1001000);
    }
}