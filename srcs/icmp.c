#include "../incs/nmap.h"

/*
**	Handle ICMP reply
**  Get offset of encapsulate packet that cause this ICMP reply
**  If this packet is a UDP datagram
**  -- Get index of target port
**  -- If not from targeted port range then stop there
**  -- If ICMP reply is port unreachable (type 3 && code 3)
**  --- Target port is CLOSED
**  -- If ICMP reply is other unreachable messages (type 3 && code 1/2/9/10/11)
**  --- Target port is CLOSED
**  If this packet is a TCP segment
**  -- Get index of target port
**  -- If not from targeted port range then stop there
**  -- If ICMP reply is unreachable (type 3 && code 1/2/3/9/10/11)
**  -- Set port state depending on scan type
*/
void handleResponse_ICMP(t_env *env, const u_char *packet, struct icmp *icmp_hdr)
{
    struct tcphdr   *tcp_hdr = NULL;
    struct udphdr   *udp_hdr = NULL;
    uint16_t        offset;
    int16_t         index;

    offset = getEncapDataOffset(packet);
    if (env->scan.current == SUDP) {
        udp_hdr = (struct udphdr *)&packet[offset];
        if ((index = isPortFromScan(env, ntohs(udp_hdr->uh_dport))) == -1 || ntohs(udp_hdr->uh_sport) != 44380)
            return ;
        if (isHostUnreachable(icmp_hdr)) {
            if (icmp_hdr->icmp_code == 3)
                env->port.result[index].udp = CLOSED;
            else
                env->port.result[index].udp = FILT;
        }
    }
    else {
        tcp_hdr = (struct tcphdr *)&packet[offset];
        if ((index = isPortFromScan(env, ntohs(tcp_hdr->th_dport))) == -1 || ntohs(tcp_hdr->th_sport) != 44380)
            return ;
        if (isHostUnreachable(icmp_hdr)) {
            switch (env->scan.current) {
                case (SSYN):    env->port.result[index].syn = FILT;   break;
                case (SACK):    env->port.result[index].ack = FILT;   break;
                case (SFIN):    env->port.result[index].fin = FILT;   break;
                case (SNULL):   env->port.result[index].null = FILT;  break;
                case (SXMAS):   env->port.result[index].xmas = FILT;  break;
            }
        }
    }
}

/*
**	Set ICMP header values
**  ICMP echo request (type 8 / code 0)
*/
void setHeader_ICMP(struct icmp *header)
{
    bzero(header, sizeof(struct icmp));

    header->icmp_type = 8;
    header->icmp_code = 0;
    header->icmp_hun.ih_idseq.icd_id = 42;
    header->icmp_cksum = calcul_checksum(header, sizeof(struct icmp));
}