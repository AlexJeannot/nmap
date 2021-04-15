#include <stdio.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/ethernet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
#include <stdlib.h>
#include <strings.h>


uint16_t	calcul_checksum(void *data, int32_t size)
{
	uint64_t	checksum;
	uint16_t	*addr;

	checksum = 0;
	addr = data;
	while (size > 1)
	{
		checksum += *addr;
		addr++;
		size -= (int)sizeof(uint16_t);
	}
	if (size == 1)
		checksum += *(uint8_t*)addr;
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);
	checksum = ~checksum;

	return ((uint16_t)checksum);
}

int main()
{
    struct sockaddr_in sender;
    int sock;

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("SOCKET FAILED:");
        exit(1);
    }

    int read_sock;
    if ((read_sock = socket(AF_INET, SOCK_RAW, htons(3))) < 0) {
        perror("SOCKET FAILED:");
        exit(1);
    }
    // ETH_P_ALL
    // struct sockaddr_in binder;
    // bzero(&binder, sizeof(binder));
    // binder.sin_family = AF_INET;
    // binder.sin_port = htons(44000);
    // binder.sin_addr.s_addr = INADDR_ANY;

    // if (bind(read_sock, (struct sockaddr *)&binder, sizeof(binder)) < 0) {
    //     perror("BIND");
    //     exit(1);
    // }

    // if ((listen(read_sock, 10)) != 0) {
    //     perror("LISTEN");
    //     exit(1);
    // }

    // int confd;
    // struct sockaddr cli;
    // socklen_t sizecli = sizeof(cli);

    // if ((confd = accept(read_sock, &cli, &sizecli)) < 0) {
    //     perror("ACCEPT");
    //     exit(1);
    // }

    // int opt = 1;
    // if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
    //     perror("setsocketopt failed");

    bzero(&sender, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_port = htons(80);
    inet_aton("45.33.32.156", &sender.sin_addr);


    struct ip ip_packet;
    bzero(&ip_packet, sizeof(ip_packet));
    ip_packet.ip_hl = 5;
    ip_packet.ip_v = 4;
    ip_packet.ip_tos = 0;
    ip_packet.ip_len = htons(40);
    ip_packet.ip_id = htons(42);
    ip_packet.ip_off = 0;
    ip_packet.ip_ttl = 64;
    ip_packet.ip_p = 6;
    ip_packet.ip_sum = calcul_checksum(&ip_packet, sizeof(struct ip));;
    inet_aton("192.168.1.68", &ip_packet.ip_src);
    inet_aton("45.33.32.156", &ip_packet.ip_dst);

    printf("sizeof(struct ip) = %lu\n", sizeof(struct ip));
    printf("sizeof(struct tcphdr) = %lu\n", sizeof(struct tcphdr));


    struct tcphdr packet;
    bzero(&packet, sizeof(packet));

    packet.th_sport = htons(44000);
    packet.th_dport = htons(80);
    packet.th_seq = 0;
    packet.th_ack = 0;
    packet.th_off = 5;
    packet.th_flags = TH_SYN;
    packet.th_win =  htons(1024);
    packet.th_sum = calcul_checksum(&packet, sizeof(struct tcphdr));
    packet.th_urp = 0;

    char data[40];
    memcpy(&data[0], &ip_packet, 20);
    memcpy(&data[20], &packet, 20);


    if ((sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *)&sender, sizeof(sender))) == -1) {
        perror("SEND FAILED:");
        exit(1);
    }


    char buf[4096];
    bzero(&buf, sizeof(buf));
    struct sockaddr_in from;
    bzero(&from, sizeof(from));
    socklen_t size = sizeof(from);

    // sleep(1);
    // fflush(stdout);

    if (recvfrom(read_sock, &buf[0], sizeof(buf), 0, (struct sockaddr *)&from, &size) == -1) {
        perror("RECV FAILED");
        exit(1);
    }

}