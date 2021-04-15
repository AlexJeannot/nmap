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

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // (void)packet;
    t_env *env = (t_env *)args;
    // printf("arg = %s\n", env->test);
    // printf("-----------------------------\n");
    // printf("TOTAL Packet with length of [%d]\n", header->len);
    // printf("CAPTURE Packet with length of [%d]\n", header->caplen);
    (void)header;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // printf("==== IP ====\n");
        display_ip_header_info((struct ip *)&packet[14]);
        if (((struct ip *)&packet[14])->ip_p == 1)
            env->ping.imcp_r = 1;
        else if (((struct ip *)&packet[14])->ip_p == 6)
            env->ping.tcp_r = 1;
        if (env->ping.imcp_r || env->ping.tcp_r) {
            printf("EXIT IN LOOP\n");
            env->ping.ts_end = get_ts_ms();
            pcap_breakloop(siginfo.handle);
            // pthread_exit((void *)0);
        }
    }
    // printf("siginfo.stop = %d\n", siginfo.stop);
}

void setFilter(t_env *env, pcap_t *handle)
{
    struct bpf_program fp;
    char filter[4096];

    if (env->s_type == S_PING) {
        sprintf(&filter[0], "src host %s && (tcp src port 80 || icmp[icmptype] == icmp-echoreply)", env->l_target->s_ip);
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