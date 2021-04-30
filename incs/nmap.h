#ifndef NMAP_H
# define NMAP_H

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <strings.h>
# include <ctype.h>
# include <poll.h>
# include <pthread.h>
# include <signal.h>
# include <string.h>

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

# define WO_COMMA   0
# define W_COMMA    1

# define ETHHDR_LEN         14
# define CHKSM_PREHDR_LEN   12

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

/*
**  Structure of machine interface
**  Use for packet creation (source IP)
*/
typedef struct  s_interface
{
    in_addr_t   n_ip;
    char        s_ip[INET_ADDRSTRLEN];
}               t_interface;

/*
**  Structure of network sockets
*/
typedef struct  s_socket
{
    int32_t     icmp;
    int32_t     tcp;
    int32_t     udp;
}               t_socket;

/*
**  Structure of a linked list element for targets
**  Store informations about target (ip/hostname)
*/
typedef struct  s_list_target
{
    in_addr_t               ip;
    struct sockaddr         n_ip;
    char                    s_ip[INET_ADDRSTRLEN];
    char                    s_host[256];
    struct s_list_target    *next;
}               t_list_target;

/*
**  Structure of targets
**  Pointer to target linked list, save (for resource clearing) and number of target
*/
typedef struct s_target
{
    t_list_target   *list;
    t_list_target   *start;
    uint64_t        nb;
}   t_target;

/*
**  Structure of result about one port
**  Values use on bit field are present at the top of this file
*/
typedef struct  s_result
{
    uint16_t    syn     :2;
    uint16_t    ack     :2;
    uint16_t    fin     :3;
    uint16_t    null    :3;
    uint16_t    xmas    :3;
    uint16_t    udp     :3;
}               t_result;

/*
**  Strcture of ports
**  Store an array of 1024 ports and 1024 result
*/
typedef struct  s_port
{
    uint16_t    nb;
    uint16_t    list[1024];
    t_result    result[1024];
}               t_port;

/*
**  Structure of thread management
**  Mutex for thread incrementation/decrementation of thread pool (nb)
**  Number of thread allocated on heap because each thread can modify it
**  Bool to know if multithreading is requested
*/
typedef struct  s_thread
{
    pthread_mutex_t lock;
    uint8_t         *nb;
    uint8_t         on;
}               t_thread;

/*
**  Structure of sniffer
**  Handler for ping step and scan step
**  Mutex for thread communication and timing
**  Booleans on sniffer state (ready/end)
*/
typedef struct  s_sniffer
{
    pcap_t              *p_handle;
    pcap_t              *s_handle;
    pthread_t           id;
    pthread_mutex_t     lock;
    uint8_t             ready;
    uint8_t             end;
}               t_sniffer;

/*
**  Structure of ping
**  Booleans about IMCP echo reply and TCP reply
*/
typedef struct  s_ping
{
    uint8_t     imcp_r;
    uint8_t     tcp_r;
}               t_ping;


/*
**  Structure of scan
**  All scan requested 
**  Current scan
*/
typedef struct  s_scan {
    uint8_t     all;
    uint8_t     current;
}               t_scan;

/*
**  Structure of statistiques about program and scans
**  Timestamps and number of host down (heap because shared among threads)
*/
typedef struct  s_stats
{
    long double g_start;
    long double g_end;
    long double s_start;
    long double s_end;
    uint64_t    *host_down;
}               t_stats;

/*
**  Main structure
*/
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

/*
**  Structure of chechsum
**  Use because TCP and UDP checksum calculation need a preheader
*/
typedef struct  s_checksum
{
    in_addr_t           s_addr;
    in_addr_t           t_addr;
    uint8_t             pad;
    uint8_t             type;
    uint16_t            length;
    union
    {
        struct tcphdr   tcp;
        struct udphdr   udp;
    }   hdr;
}               t_checksum;

/*
**  Pointer to main structure (only use in case of interruption signal)
*/
t_env *sig_env;

void *packetSniffer(void *input);
void parseArgs(t_env *env, int argc, char **argv);
void	errorMsgExit(t_env *env, char *option, char *arg);
long double	getTsMs(void);
void waitForReponse(t_env *env);
void setSignalHandler(t_env *env);

/*
** ANNEXES.C
*/
void        setDefaultPortState(t_env *env);
void        initProgram(t_env *env);
void        setDefautParams(t_env *env);
void        sortPort(t_env *env);

/*
** CONTROL.C
*/
int8_t      isHostUp(const t_env *env);
int16_t     isPortFromScan(const t_env *env, uint16_t port);
int8_t      isHostUnreachable(struct icmp *icmp_hdr);
uint8_t     isHostDuplicate(t_env *env, struct hostent *host);
int8_t      isOption(t_env *env, char *arg);
void        isUserRoot(t_env *env);

/*
** DISPLAY.C
*/
void        displayHelp(t_env *env, int code);
int8_t      displayHostUp(t_env *env);
int8_t      displayHostDown(t_env *env);
void        displayResults(t_env *env);
void        displayConclusion(t_env *env);
void        displayIntroduction(t_env *env);

/*
** EXEC.C
*/
void        execWithoutThreads(t_env *env);
void        execWithThreads(t_env *main_env);

/*
** EXIT.C
*/
void	    errorMsgExit(t_env *env, char *option, char *arg);
void        clearResources(t_env *env, char *error);

/*
** ICMP.C
*/
void        handleResponse_ICMP(t_env *env, const u_char *packet, struct icmp *icmp_hdr);
void        setHeader_ICMP(struct icmp *header);

/*
** NETWORK.C
*/
void        createSocket(t_env *env);
void        setTargetPort(struct sockaddr *target, uint16_t port);
void        getSourceIP(t_env *env);
uint16_t    getEncapDataOffset(const u_char *packet);
uint16_t    getMinPort(const t_env *env);
uint16_t    getMaxPort(const t_env *env);
uint16_t	calcul_checksum(void *data, int32_t size);

/*
** PARSE.C
*/
uint32_t    addPortRange(t_env *env, char *input, int32_t fport, int32_t sport);
void        parseScan(t_env *env, char *input);

/*
**  PING.C
*/
void        handleResponse_ping(t_env *env, struct ip *hdr);
int8_t      pingTarget(t_env *env);

/*
** SCAN.C
*/
void        scanTarget(t_env *env);
void        *execScan(void *input);

/*
** SIGNAL.C
*/
void        setSignalHandler(t_env *env);

/*
**  SNIFFER.C
*/
void        *packetSniffer(void *input);

/*
** TCP.C
*/
void        handleResponse_TCP(t_env *env, struct tcphdr *hdr);
void        setHeader_TCP(t_env *env, struct tcphdr *header, uint16_t port);
void        sendSegment(t_env *env);

/*
** THREAD.C
*/
int8_t      isThreadAvailable(t_env *env);
void        decrementThreadPool(t_env *env);
void        incrementThreadPool(t_env *env);
void        setSnifferState(t_env *env, uint8_t *sniffer, uint8_t state);

/*
** TIME.C
*/
long double getTsMs(void);
void        waitForSniffer(t_env *env);
void        waitForEndSniffer(t_env *env);
void        waitForReponse(t_env *env);
void        waitForSender(pthread_t *ids, uint64_t target_nb);
void        waitForPing(t_env *env);

/*
** UDP.C
*/
void        handleReponse_UDP(t_env *env, struct udphdr *hdr);
void        sendDatagram(t_env *env);

#endif