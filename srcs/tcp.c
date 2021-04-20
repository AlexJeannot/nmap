#include "../incs/nmap.h"

void setHeader_TCP(struct tcphdr *header, t_probe_info *info)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &info->intf_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &((struct sockaddr_in *)&info->target)->sin_addr, sizeof(in_addr_t));
    chk.type = IPPROTO_TCP;
    chk.length = htons((uint16_t)sizeof(struct tcphdr));

    bzero(header, sizeof(struct tcphdr));
    header->th_sport = htons(44380);
    header->th_dport = htons(info->port);
    header->th_seq = 0; // TODO
    header->th_ack = 0;
    header->th_off = 5;
    header->th_win =  htons(1024);
    header->th_urp = 0;

    switch (info->type) {
        case (SSYN):    header->th_flags = TH_SYN;                      break;
        case (SACK):    header->th_flags = TH_ACK;                      break;
        case (SNULL):   header->th_flags = 0;                           break;
        case (SFIN):    header->th_flags = TH_FIN;                      break;
        case (SXMAS):   header->th_flags = TH_FIN | TH_PUSH | TH_URG;   break;
    }

    memcpy(&chk.hdr.tcp, header, sizeof(struct tcphdr));
    header->th_sum = calcul_checksum(&chk, sizeof(struct tcphdr) + CHKSM_PREHDR_LEN);
}

void *sendSegment(void *input)
{
    struct tcphdr tcp_header;
    t_probe_info    *info;

    info = (t_probe_info *)input;
    setHeader_TCP(&tcp_header, info);
    printf("sendSegment tcp_header.dport = %d\n", ntohs(tcp_header.th_dport));
    if (sendto(info->sock, &tcp_header, sizeof(struct tcphdr), 0, &info->target, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "TCP scan");
    
    if (info->is_thread) {
        pthread_exit((void*)0);
    }
    return ((void *)1);
}

void sendAllSegment(t_env *env, uint8_t type)
{
    t_probe_info info;
    long double bef;
    long double after;


    bef = get_ts_ms();

    setProbeInfo(env, &info, type);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setProbePort(&info, env->port.list[pos]);

        if (isThreadAvailable(env))
            sendSegmentByThread(info);
        else
            sendSegment(&info);


        // if (pos % 100 == 0)
        //     usleep(100000);
    }
    after = get_ts_ms();
    printf("TIME = %LF ms\n", (after - bef));
}