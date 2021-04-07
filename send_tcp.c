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


int main()
{
    struct sockaddr_in sender;
    int sock;

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("SOCKET FAILED:");
        exit(1);
    }

    bzero(&sender, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_port = 41200;
    inet_aton("45.33.32.156", &sender.sin_addr);

    struct tcphdr packet;

    bzero(&packet, sizeof(packet));

    packet.th_sport = htons(44004);
    packet.th_dport = htons(44005);
    packet.th_seq = 0;
    packet.th_ack = 0;
    packet.th_off = 5;
    packet.th_flags = TH_SYN;
    packet.th_win =  htons(1024);
    packet.th_sum = 120;
    packet.th_urp = 0;

    if ((sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *)&sender, sizeof(sender))) == -1) {
        perror("SEND FAILED:");
        exit(1);
    }
}