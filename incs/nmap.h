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

typedef struct  s_interface
{
    in_addr_t   n_ip;
    char        s_ip[INET_ADDRSTRLEN];
}               t_interface;

typedef struct  s_checksum
{
    in_addr_t           s_addr;
    in_addr_t           t_addr;
    uint8_t             pad;
    uint8_t             type;
    uint16_t            length;
    union {
        struct tcphdr   tcp;
        struct udphdr   udp;
    }   hdr;
}               t_checksum;

typedef struct  s_list_target
{
    in_addr_t               ip;
    struct sockaddr         n_ip;
    char                    s_ip[INET_ADDRSTRLEN];
    char                    s_host[256];
    struct s_list_target    *next;
}               t_list_target;

typedef struct s_target
{
    t_list_target   *list;
    t_list_target   *start;
    uint64_t        nb;
}   t_target;

typedef struct  s_ping
{
    uint8_t     imcp_r;
    uint8_t     tcp_r;
}               t_ping;

typedef struct  s_result
{
    uint16_t    syn     :2;
    uint16_t    ack     :2;
    uint16_t    fin     :3;
    uint16_t    null    :3;
    uint16_t    xmas    :3;
    uint16_t    udp     :3;
}               t_result;

typedef struct  s_port
{
    uint16_t    nb;
    uint16_t    list[1024];
    t_result    result[1024];
    // pthread_mutex_t lock;
}               t_port;

typedef struct  s_socket
{
    int32_t     icmp;
    int32_t     tcp;
    int32_t     udp;
}               t_socket;

typedef struct  s_scan {
    uint8_t     all;
    uint8_t     current;
}               t_scan;

typedef struct  s_thread
{
    pthread_mutex_t lock;
    uint8_t         *nb;
    uint8_t         on;
}               t_thread;

typedef struct  s_stats
{
    long double g_start;
    long double g_end;
    long double s_start;
    long double s_end;
    uint64_t    *host_down;
}               t_stats;

typedef struct  s_sniffer
{
    pcap_t              *p_handle;
    pcap_t              *s_handle;
    pthread_t           id;
    pthread_mutex_t     lock;
    uint8_t             ready;
    uint8_t             end;
}               t_sniffer;

typedef struct  s_env
{
    t_interface     intf;
    t_socket        sock;
    t_target        target;
    t_port          port;
    t_thread        thread;
    t_sniffer       sniffer;
    t_ping          ping;
    t_scan          scan;
    t_stats         stats;
    pthread_mutex_t display_lock;
    struct s_env    *main_env;
}                   t_env;

void *packetSniffer(void *input);
void parseArgs(t_env *env, int argc, char **argv);
void	errorMsgExit(t_env *env, char *option, char *arg);
long double	get_ts_ms(void);
void waitForReponse(t_env *env);

/*
** TCP.C
*/
void handleResponse_TCP(t_env *env, struct tcphdr *hdr);
void setHeader_TCP(t_env *env, struct tcphdr *header, uint16_t port);
void sendSegment(t_env *env);

/*
**  PING.C
*/
void handleResponse_ping(t_env *env, struct ip *hdr);
int8_t pingTarget(t_env *env);

/*
** UDP.C
*/
void handleReponse_UDP(t_env *env, struct udphdr *hdr);
void sendDatagram(t_env *env);

/*
** ICMP.C
*/
void handleResponse_ICMP(t_env *env, const u_char *packet, struct icmp *icmp_hdr);
void setHeader_ICMP(struct icmp *header);

/*
** TIME.C
*/
long double	get_ts_ms(void);
void waitForSniffer(t_env *env);
void waitForEndSniffer(t_env *env);
void waitForReponse(t_env *env);
void waitForPingReponse(t_env *env);
void waitForSender(pthread_t *ids, uint64_t target_nb);

/*
** EXEC.C
*/
void execWithoutThreads(t_env *env);
void execWithThreads(t_env *main_env);

/*
** SCAN.C
*/
void scanTarget(t_env *env);
void *execScan(void *input);


/*
** NETWORK.C
*/
void createSocket(t_env *env);
void setTargetPort(struct sockaddr *target, uint16_t port);
uint16_t getEncapDataOffset(const u_char *packet);
void getSourceIP(t_env *env);


int8_t getPortIndex(t_env *env);
int16_t setPortIndex(t_env *env);

uint16_t	calcul_checksum(void *data, int32_t size);
uint16_t getMaxPort(const t_env *env);
uint16_t getMinPort(const t_env *env);
/*
** CONTROL.C
*/
int8_t isHostUp(const t_env *env);
int16_t  isPortFromScan(const t_env *env, uint16_t port);
int8_t  isHostUnreachable(struct icmp *icmp_hdr);
uint8_t isHostDuplicate(t_env *env, struct hostent *host);
int8_t isOption(t_env *env, char *arg);

/*
** DISPLAY.C
*/
void displayHelp(t_env *env, int code);
int8_t displayHostUp(t_env *env);
int8_t displayHostDown(t_env *env);
void displayResults(t_env *env);
void displayConclusion(t_env *env);
void displayIntroduction(t_env *env);

/*
** THREAD.C
*/
int8_t  isThreadAvailable(t_env *env);
void decrementThreadPool(t_env *env);
void incrementThreadPool(t_env *env);
void setSnifferState(t_env *env, uint8_t *sniffer, uint8_t state);

/*
** ANNEXES.C
*/
void setDefaultPortState(t_env *env);
void initProgram(t_env *env);
void setDefautParams(t_env *env);
void sortPort(t_env *env);

/*
** PARSE.C
*/
uint32_t addPortRange(t_env *env, char *input, int32_t fport, int32_t sport);
void parseScan(t_env *env, char *input);

/*
** EXIT.C
*/
void clearResources(t_env *env, char *error);


#endif