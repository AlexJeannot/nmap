#include "../incs/nmap.h"

void display_ip_header_info(struct ip *header)
{
    printf("\n=================== DISPLAY IP ===================\n");
    printf("version = %u\n", header->ip_v);
    printf("header_size = %u\n", header->ip_hl);
    printf("dscp = %u\n", header->ip_tos & 0xfc);
    printf("ecn = %u\n", header->ip_tos & 0x3);
    printf("packet_size = %u\n", ntohs(header->ip_len));
    printf("id = %u\n", header->ip_id);
    printf("flags = %u\n", header->ip_off & 0xe000);
    printf("offset = %u\n", header->ip_off & 0x1fff);
    printf("ttl = %u\n", header->ip_ttl);
    printf("protocol = %u\n", header->ip_p);
    printf("checksum = %u\n", header->ip_sum);
    printf("s_addr = %s\n", inet_ntoa(header->ip_src));
    printf("d_addr = %s\n", inet_ntoa(header->ip_dst));

    write(1, "\n\n", 2);
}

int16_t  isPortFromScan(const t_env *env, uint16_t port)
{
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] == port)
            return (pos);
    }
    return (-1);
}

void handleResponse_ping(t_env *env, struct ip *ip_hdr)
{
    if (ip_hdr->ip_p == IPPROTO_ICMP)
        env->ping.imcp_r = 1;
    else if (ip_hdr->ip_p == IPPROTO_TCP)
        env->ping.tcp_r = 1;
    else 
        return ;

    env->ping.ts_end = get_ts_ms();
    // pcap_breakloop(siginfo.handle);
}

void handleReponse_UDP(t_env *env, struct udphdr *udp_hdr)
{
    int16_t        index;

    printf("UDP FCT SRC PORT = %d\n", ntohs(udp_hdr->uh_sport));
    printf("UDP FCT DEST PORT = %d\n", ntohs(udp_hdr->uh_dport));

    if ((index = isPortFromScan(env, ntohs(udp_hdr->uh_sport))) == -1 || ntohs(udp_hdr->uh_dport) != 44380)
        return ;

    env->port.result[index].udp = OPEN;
}

int8_t  isHostUnreachable(struct icmp *icmp_hdr)
{
    u_char  type;
    u_char  code;

    type = icmp_hdr->icmp_type;
    code = icmp_hdr->icmp_code;
    if (type == 3 || code == 1 || code == 2 || code == 3
        || code == 9 || code == 10 || code == 13)
        return (TRUE);
    return (FALSE);
}

void handleResponse_TCP(t_env *env, struct tcphdr *tcp_hdr)
{
    int16_t        index;

    if ((index = isPortFromScan(env, ntohs(tcp_hdr->th_sport))) == -1 || ntohs(tcp_hdr->th_dport) != 44380)
        return ;

    if ((tcp_hdr->th_flags & TH_SYN) && (tcp_hdr->th_flags & TH_ACK)) {
        if (env->scan.current == SSYN)
            env->port.result[index].syn = OPEN;
    }
    else if ((tcp_hdr->th_flags & TH_RST)) {
        switch (env->scan.current) {
            case (SSYN):    env->port.result[index].syn = CLOSED;   break;
            case (SACK):    env->port.result[index].ack = UNFILT;   break;
            case (SFIN):    env->port.result[index].fin = CLOSED;   break;
            case (SNULL):   env->port.result[index].null = CLOSED;  break;
            case (SXMAS):   env->port.result[index].xmas = CLOSED;  break;
        }
    }
}

uint16_t getEncapDataOffset(const u_char *packet)
{
    struct ip   *ip_hdr;
    uint16_t    offset;

    offset = ETHHDR_LEN;
    ip_hdr = (struct ip *)&packet[offset];
    offset += (ip_hdr->ip_hl * 4) + ICMP_MINLEN;
    ip_hdr = (struct ip *)&packet[offset];
    offset += (ip_hdr->ip_hl * 4);
    return (offset);
}

void handleResponse_ICMP(t_env *env, const u_char *packet, struct icmp *icmp_hdr)
{
    struct tcphdr   *tcp_hdr = NULL;
    struct udphdr   *udp_hdr = NULL;
    uint16_t        offset;
    int16_t        index;

    offset = getEncapDataOffset(packet);
    if (env->scan.current == SUDP) {
        udp_hdr = (struct udphdr *)&packet[offset];
        printf("[ICMP] PORT UDP SRC = %d\n", ntohs(udp_hdr->uh_sport));
        printf("[ICMP] PORT UDP DST = %d\n", ntohs(udp_hdr->uh_dport));
        if ((index = isPortFromScan(env, ntohs(udp_hdr->uh_dport))) == -1 || ntohs(udp_hdr->uh_sport) != 44380)
            return ;
        printf("index = %d\n", index);
        if (isHostUnreachable(icmp_hdr)) {
            if (icmp_hdr->icmp_code == 3)
                env->port.result[index].udp = CLOSED;
            else
                env->port.result[index].udp = FILT;
        }
        printf("env->port.result[index].udp = %d\n", env->port.result[index].udp);
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

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // printf("-----------------------------\n");
    // printf("TOTAL Packet with length of [%d]\n", header->len);
    // printf("CAPTURE Packet with length of [%d]\n", header->caplen);
    (void)header;
    t_env *env;
    struct ether_header *eth_hdr;
    struct ip           *ip_hdr;

    env = (t_env *)args;
    eth_hdr = (struct ether_header *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        // display_ip_header_info((struct ip *)&packet[14]);
        ip_hdr = (struct ip *)&packet[ETHHDR_LEN];
        if (env->scan.current == SPING)
            handleResponse_ping(env, ip_hdr);
        else if (ip_hdr->ip_p == IPPROTO_ICMP)
            handleResponse_ICMP(env, packet, (struct icmp *)&packet[ETHHDR_LEN + (ip_hdr->ip_hl * 4)]);
        else if (env->scan.current == SUDP)
            handleReponse_UDP(env, (struct udphdr *)&packet[ETHHDR_LEN + (ip_hdr->ip_hl * 4)]);
        else
            handleResponse_TCP(env, (struct tcphdr *)&packet[ETHHDR_LEN + (ip_hdr->ip_hl * 4)]);
    }
}

void setFilter(t_env *env, pcap_t *handle)
{
    struct bpf_program fp;
    char filter[4096];

    if (env->scan.current == SPING) {
        sprintf(&filter[0], "src host %s && (tcp src port 80 || icmp[icmptype] == icmp-echoreply)", env->l_target->s_ip);
    }
    else if (env->scan.current == SUDP) {
        sprintf(&filter[0], "src host %s", env->l_target->s_ip);
        sprintf(&filter[strlen(filter)], " && (udp src portrange %d-%d ", getMinPort(env), getMaxPort(env));
        sprintf(&filter[strlen(filter)], " || icmp[icmptype] == icmp-unreach)");
        printf("FILTER UDP = %s\n", filter);
    }
    else {
        sprintf(&filter[0], "src host %s", env->l_target->s_ip);
        sprintf(&filter[strlen(filter)], " && (tcp src portrange %d-%d ", getMinPort(env), getMaxPort(env));
        sprintf(&filter[strlen(filter)], " || icmp[icmptype] == icmp-unreach)");
        printf("FILTER TCP = %s\n", filter);
    }

    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        errorMsgExit("pcap compilation", pcap_geterr(handle));

    if (pcap_setfilter(handle, &fp) == -1)
        errorMsgExit("pcap filter setting", pcap_geterr(handle));
}

void setupCapture(pcap_t **handle)
{
    pcap_if_t *dlist;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&dlist, errbuf) == -1)
        errorMsgExit("pcap device list", errbuf);

    if (!(dlist->name))
        errorMsgExit("pcap device name", "no name found");

    if (!(*handle = pcap_open_live(dlist->name, 84, 0, 10, errbuf)))
        errorMsgExit("pcap device opening", errbuf);
}

void signal_handler_thread(int code)
{
    if (code == SIGALRM) {
        pcap_breakloop(siginfo.handle);
    }
}

void *packetSniffer(void *env)
{
    setupCapture(&siginfo.handle);
    setFilter(env, siginfo.handle);
    signal(SIGALRM, signal_handler_thread);
    pcap_loop(siginfo.handle, 0, my_packet_handler, env);
    pcap_close(siginfo.handle);

    return ((void *)0);
}