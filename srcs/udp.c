#include "../incs/nmap.h"

void setHeader_UDP(struct udphdr *hdr, t_probe_info *info)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &info->intf_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &((struct sockaddr_in *)&info->target)->sin_addr, sizeof(in_addr_t));
    chk.type = IPPROTO_UDP;
    chk.length = htons((uint16_t)sizeof(struct udphdr)+ 14);

    hdr->uh_dport = htons(info->port);
    hdr->uh_sport = htons(44380);
    hdr->uh_ulen = htons(22);

    memcpy(&chk.hdr.udp, hdr, sizeof(struct udphdr));
    hdr->uh_sum = calcul_checksum(&chk, sizeof(struct udphdr) + CHKSM_PREHDR_LEN);
}

void *sendDatagram(void *input)
{
    struct udphdr udp_hdr;
    char data[22];
    t_probe_info    *info;

    info = (t_probe_info *)input;
    setHeader_UDP(&udp_hdr, info);
    bzero(&data[0], 22);
    memcpy(&data[0], &udp_hdr, sizeof(struct udphdr));
    if (sendto(info->sock, &data, 22, 0, &info->target, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "UDP scan");

    if (info->is_thread)
        pthread_exit((void*)0);
    return ((void *)0);
}

void sendAllDatagram(t_env *env)
{
    t_probe_info info;
    long double bef;
    long double after;

    bef = get_ts_ms();
    setProbeInfo(env, &info, SUDP);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setProbePort(&info, env->port.list[pos]);

        if (isThreadAvailable(env))
            sendDatagramByThread(info);
        else
            sendDatagram(&info);

        // if (pos % 100 == 0)
        //     usleep(100000);
    }
    after = get_ts_ms();
    printf("TIME = %LF ms\n", (after - bef));
}