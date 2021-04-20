#include "../incs/nmap.h"

void setHeader_ICMP(struct icmp *header)
{
    bzero(header, sizeof(struct icmp));

    header->icmp_type = 8;
    header->icmp_code = 0;
    header->icmp_hun.ih_idseq.icd_id = 42;
    header->icmp_cksum = calcul_checksum(header, sizeof(struct icmp));
}