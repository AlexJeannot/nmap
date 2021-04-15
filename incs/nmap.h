#ifndef NMAP_H
# define NMAP_H

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <strings.h>
# include <ctype.h>
# include <poll.h>
# include <pthread.h>

# include <net/ethernet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>

# include <netdb.h>
# include <pcap/pcap.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <ifaddrs.h>

# define TRUE 1
# define FALSE 0

# define WO_COMMA 0
# define W_COMMA 1

# define S_PING 0
# define S_SCAN 1

# define SSYN 0x1
# define SACK 0x2
# define SNULL 0x4
# define SFIN 0x8
# define SXMAS 0x10
# define SUDP 0x20

typedef struct  s_interface {
    in_addr_t   n_ip;
    char        s_ip[INET_ADDRSTRLEN];
}               t_interface;

typedef struct s_sig_info {
    pcap_t *handle;
}   t_sig_info;

typedef struct  s_tcp_checksum
{
    in_addr_t       s_addr;
    in_addr_t       t_addr;
    uint8_t         pad;
    uint8_t         type;
    uint16_t        length;
    struct tcphdr   tcp;
}       t_tcp_checksum;

typedef struct s_target
{
    in_addr_t       ip;
    char            s_ip[INET_ADDRSTRLEN];
    char            s_host[256];
    struct s_target *next;
}   t_target;

typedef struct s_ping {
    pthread_t id;
    long double ts_start;
    long double ts_end;
    uint8_t     imcp_r;
    uint8_t     tcp_r;
}   t_ping;

typedef struct s_env {

    uint16_t    port_list[1024];
    uint16_t    nb_port;
    t_target    *l_target;
    uint8_t     thread_nb;
    uint8_t     scan_type;
    char        test[10];
    t_ping      ping;
    uint8_t     s_type;
    t_interface intf;
} t_env;

t_sig_info siginfo;

uint16_t	calcul_checksum(void *data, int32_t size);
void *packetSniffer(void *env);
void parseArgs(t_env *env, int argc, char **argv);
void	errorMsgExit(char *option, char *arg);
long double	get_ts_ms(void);

void setHeader_TCP(const t_env *env, struct tcphdr *header, uint16_t port);

#endif