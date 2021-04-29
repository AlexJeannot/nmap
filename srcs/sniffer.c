#include "../incs/nmap.h"

/*
**  Packet handler
**  Analyze each packet on interface that match filter
**  If ethernet frame
**  -- If current scan type is ping then call ping reply handler
**  -- If packet IP protocol is ICMP then call ICMP reply handler
**  -- If current scan type is UDP then call UDP reply handler
**  -- Else call TCP reply handler
*/
void    packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    t_env               *env;
    struct ether_header *eth_hdr;
    struct ip           *ip_hdr;

    (void)header;
    env = (t_env *)args;
    eth_hdr = (struct ether_header *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
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

/*
**  Set filter for packet capture accordingly to interesting packet for each situation
**  Create filter
**  Compile filter
**  Set filter
*/
void    setFilter(t_env *env)
{
    struct bpf_program  fp;
    char                filter[4096];
    pcap_t              **handle;

    handle = (env->scan.current == SPING) ? &env->sniffer.p_handle : &env->sniffer.s_handle;
    if (env->scan.current == SPING) {
        sprintf(&filter[0], "src host %s && (tcp src port 80 || icmp[icmptype] == icmp-echoreply)", env->target.list->s_ip);
    }
    else if (env->scan.current == SUDP) {
        sprintf(&filter[0], "src host %s", env->target.list->s_ip);
        sprintf(&filter[strlen(filter)], " && (udp src portrange %d-%d ", getMinPort(env), getMaxPort(env));
        sprintf(&filter[strlen(filter)], " || icmp[icmptype] == icmp-unreach)");
    }
    else {
        sprintf(&filter[0], "src host %s", env->target.list->s_ip);
        sprintf(&filter[strlen(filter)], " && (tcp src portrange %d-%d ", getMinPort(env), getMaxPort(env));
        sprintf(&filter[strlen(filter)], " || icmp[icmptype] == icmp-unreach)");
    }

    if (pcap_compile(*handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        errorMsgExit(env, "pcap compilation", pcap_geterr(*handle));

    if (pcap_setfilter(*handle, &fp) == -1)
        errorMsgExit(env, "pcap filter setting", pcap_geterr(*handle));

    pcap_freecode(&fp);
}

/*
**  Prepare handler for packet capture
**  Timer is ms before reading buffer with all store packets (1000 for ping / 100 otherwise)
**  Find all devices
**  If no device found then exit here
**  Open handler for packet capture
*/
void setupCapture(t_env *env)
{
    pcap_if_t   *dlist;
    pcap_t      **handle;
    char        errbuf[PCAP_ERRBUF_SIZE];
    int32_t     timer;

    timer = (env->scan.current == SPING) ? 1000 : 100;
    handle = (env->scan.current == SPING) ? &env->sniffer.p_handle : &env->sniffer.s_handle;
    if (pcap_findalldevs(&dlist, errbuf) == -1)
        errorMsgExit(env, "pcap device list", errbuf);

    if (!(dlist->name))
        errorMsgExit(env, "pcap device name", "no name found");

    if (!(*handle = pcap_open_live(dlist->name, BUFSIZ, 1, timer, errbuf)))
        errorMsgExit(env, "pcap device opening", errbuf);

    pcap_freealldevs(dlist);
}

/*
**  Packet sniffer main function
**  Setup handler for capture
**  Setup filter
**  Set sniffer ready for other thread communication
**  If ping
**  -- Wait for pcap_dispatch to finish (1000ms as set in setupCapture())
**  Else
**  -- While pcap_breakloop is not call from other thread then loop analyzing packets (1000ms after last packet sent)
**  Close handler
**  Set sniffer finished for other thread communication
*/
void *packetSniffer(void *input)
{
    t_env   *env;
    int32_t ret;

    env = (t_env *)input;
    (env->scan.current == SPING) ? setupCapture(env) : setupCapture(env);
    (env->scan.current == SPING) ? setFilter(env) : setFilter(env);

    setSnifferState(env, &env->sniffer.ready, TRUE);
    if (env->scan.current == SPING)
        ret = pcap_dispatch(env->sniffer.p_handle, -1, packetHandler, (void *)env);
    else
        while ((ret = pcap_dispatch(env->sniffer.s_handle, 0, packetHandler, (void *)env)) != -2) ;

    (env->scan.current == SPING) ? pcap_close(env->sniffer.p_handle) : pcap_close(env->sniffer.s_handle);
    if (env->scan.current == SPING)
        env->sniffer.p_handle = NULL;
    else
        env->sniffer.s_handle = NULL;
    setSnifferState(env, &env->sniffer.end, TRUE);

    return ((void *)0);
}