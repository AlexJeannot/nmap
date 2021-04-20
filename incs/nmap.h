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
# include <netinet/udp.h>

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
# define ETHHDR_LEN 14
# define CHKSM_PREHDR_LEN 12

# define SPING  0x0
# define SSYN   0x1
# define SACK   0x2
# define SNULL  0x4
# define SFIN   0x8
# define SXMAS  0x10
# define SUDP   0x20

# define OPEN       0x1
# define UNFILT     0x1
# define FILT       0x2
# define CLOSED     0x3
# define OPEN_FILT  0x4

typedef struct  s_interface {
    in_addr_t   n_ip;
    char        s_ip[INET_ADDRSTRLEN];
}               t_interface;

typedef struct s_sig_info {
    pcap_t *handle;
}   t_sig_info;

typedef struct  s_checksum
{
    in_addr_t       s_addr;
    in_addr_t       t_addr;
    uint8_t         pad;
    uint8_t         type;
    uint16_t        length;
    union {
        struct tcphdr   tcp;
        struct udphdr   udp;
    }   hdr;
}       t_checksum;

typedef struct s_target
{
    in_addr_t       ip;
    char            s_ip[INET_ADDRSTRLEN];
    char            s_host[256];
    struct sockaddr n_ip;
    struct s_target *next;
}   t_target;

typedef struct s_ping {
    long double ts_start;
    long double ts_end;
    uint8_t     imcp_r;
    uint8_t     tcp_r;
}   t_ping;

typedef struct  s_result {
    uint16_t    syn     :2;
    uint16_t    ack     :2;
    uint16_t    fin     :3;
    uint16_t    null    :3;
    uint16_t    xmas    :3;
    uint16_t    udp     :3;
}               t_result;

typedef struct  s_port {
    uint16_t    nb;
    uint16_t    list[1024];
    t_result    result[1024];

    pthread_mutex_t lock;
    uint16_t    index;

}               t_port;

typedef struct  s_socket
{
    int32_t     icmp;
    int32_t     tcp;
    int32_t     udp;
}               t_socket;

typedef struct s_scan {
    uint8_t all;
    uint8_t current;
}               t_scan;

typedef struct s_thread
{
    pthread_mutex_t lock;
    uint8_t         nb;
    uint8_t         on;
}               t_thread;

typedef struct s_probe_info
{
    in_addr_t       intf_ip;
    struct sockaddr target;
    int32_t         sock;
    uint16_t        port;
    uint8_t         type;
    uint8_t         is_thread;
}               t_probe_info;

typedef struct s_env {

    t_port      port;
    t_target    *l_target;

    // uint8_t     thread_nb;
    t_thread    thread;




    char        test[10];
    t_ping      ping;

    // uint8_t     scan_type;
    // uint8_t     s_type;
    t_scan      scan;

    t_interface intf;
    t_socket    sock;
    pthread_t   sniffer_id;
} t_env;

t_sig_info siginfo;

void *packetSniffer(void *env);
void parseArgs(t_env *env, int argc, char **argv);
void	errorMsgExit(char *option, char *arg);
long double	get_ts_ms(void);

/*
** TCP.C
*/
void setHeader_TCP(t_env *env, struct tcphdr *header, uint16_t port);
void sendSegment(t_env *env, uint16_t port);
void sendAllSegment(t_env *env);

/*
** UDP.C
*/
void sendDatagram(t_env *env, uint16_t port);
void sendAllDatagram(t_env *env);

/*
** ICMP.C
*/
void setHeader_ICMP(struct icmp *header);

/*
** NETWORK.C
*/
void createSocket(t_env *env);
void setTargetPort(struct sockaddr *target, uint16_t port);
void getSourceIP(t_env *env);

void setProbeInfo(t_env *env, t_probe_info *info, uint8_t type);
void setProbePort(t_probe_info *info, uint16_t port);

int8_t getPortIndex(t_env *env);
int16_t setPortIndex(t_env *env);

uint16_t	calcul_checksum(void *data, int32_t size);
uint16_t getMaxPort(const t_env *env);
uint16_t getMinPort(const t_env *env);
/*
** CONTROL.C
*/
int8_t isHostUp(const t_env *env);

/*
** DISPLAY.C
*/
int8_t displayHostUp(const t_env *env);
int8_t displayHostDown(const t_env *env);
void displayResults(const t_env *env);

/*
** THREAD.C
*/
int8_t  isThreadAvailable(t_env *env);
void decrementThreadPool(t_env *env);
void incrementThreadPool(t_env *env);
void sendDatagramByThread(t_probe_info info);
void sendSegmentByThread(t_probe_info info);

#endif