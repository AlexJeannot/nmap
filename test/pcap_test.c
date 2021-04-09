#include <stdio.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/ethernet.h>
# include <netinet/ip.h>

#define GREEN "\033[38;5;82m"
#define BLUE "\033[38;5;31m"
#define PINK "\033[38;5;207m"
#define RESET "\033[0m"

void display_ip_header_info(struct ip *header)
{
    printf("\n=================== DISPLAY IP ===================\n");
    printf("version = %u\n", header->ip_v);
    printf("header_size = %u\n", header->ip_hl);
    printf("dscp = %u\n", header->ip_tos & 0xfc);
    printf("ecn = %u\n", header->ip_tos & 0x3);
    printf("packet_size = %u\n", header->ip_len);
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

void displayDeviceInfo(struct pcap_addr *info)
{
    int count = 0;
    char *addr, *netmask, *broadaddr, *dstaddr;

    for (struct pcap_addr *tmp = info; tmp; tmp = tmp->next) {
        printf("%s--------------- ADDR %d -----------------%s\n", BLUE, count++, RESET);
        printf("FAIMILY = %d\n", ((struct sockaddr_in *)tmp->addr)->sin_family);
        printf("tmp->addr = %p\n", tmp->addr);
        printf("tmp->netmask = %p\n", tmp->netmask);
        printf("tmp->broadaddr = %p\n", tmp->broadaddr);
        printf("tmp->dstaddr = %p\n", tmp->dstaddr);
        printf("%s---------------%s\n", PINK, RESET);
        if (tmp->addr) {
            addr = inet_ntoa(((struct sockaddr_in *)tmp->addr)->sin_addr);
            printf("addr = %s\n", addr);
        }
        if (tmp->netmask) {
            netmask = inet_ntoa(((struct sockaddr_in *)tmp->netmask)->sin_addr);
            printf("netmask = %s\n", netmask);
        }
        if (tmp->broadaddr) {
            broadaddr = inet_ntoa(((struct sockaddr_in *)tmp->broadaddr)->sin_addr);
            printf("broadaddr = %s\n", broadaddr);
        }
        if (tmp->dstaddr) {
            dstaddr = inet_ntoa(((struct sockaddr_in *)tmp->dstaddr)->sin_addr);
            printf("dstaddr = %s\n", dstaddr); 
        }
    }
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // (void)packet;
    (void)args;
    printf("-----------------------------\n");
    printf("TOTAL Packet with length of [%d]\n", header->len);
    printf("CAPTURE Packet with length of [%d]\n", header->caplen);
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("==== IP ====\n");
        display_ip_header_info((struct ip *)&packet[14]);
    }
}

int main()
{
    // char *dev;
    pcap_if_t *dlst;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&dlst, errbuf) == -1) {
        fprintf(stderr, "could not find default device list: %s\n", errbuf);
        return (1);
    }

    int count = 0;
    for (pcap_if_t *tmp = dlst; tmp; tmp = tmp->next) {
        printf("%s================== DEVICE %d =======================%s\n", GREEN, count++, RESET);
        printf("name = %s\n", tmp->name);
        printf("description = %s\n", tmp->description);
        displayDeviceInfo(tmp->addresses);
    }
    printf("==========================================================\n==========================================================\n");
    pcap_t *handle;
    if (!(handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf))) {
        fprintf(stderr, "could open device: %s\n", errbuf);
        return (1);
    }
    else
        printf("Device en0 opened\n");

    struct bpf_program fp;
    char filter_exp[] = "port 80";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "could compile device: %s\n", pcap_geterr(handle));
        return (1);
    }
    else
        printf("Device en0 compiled\n");

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "could compile device: %s\n", pcap_geterr(handle));
        return (1);
    }
    struct pcap_pkthdr header;
    // const u_char *packet;

    // packet = pcap_next(handle, &header);
    /* typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *); */
    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);
    write(1, &header.comment[0], 256);
    return (0);
}