#ifndef NMAP_H
# define NMAP_H

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <strings.h>
# include <ctype.h>

# include <net/ethernet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>

# include <netdb.h>
# include <pcap/pcap.h>
# include <sys/socket.h>
# include <arpa/inet.h>


# define TRUE 1
# define FALSE 0
# define WO_COMMA 0
# define W_COMMA 1
# define W_DASH 2

# define SSYN 0x1
# define SACK 0x2
# define SNULL 0x4
# define SFIN 0x8
# define SXMAS 0x10
# define SUDP 0x20

typedef struct s_target
{
    in_addr_t       ip;
    struct s_target *next;
}   t_target;

typedef struct s_env {

    uint16_t    port_list[1024];
    uint16_t    nb_port;
    t_target    *l_target;
    uint8_t     thread_nb;
    uint8_t     scan_type;
} t_env;

void parseArgs(t_env *env, int argc, char **argv);
void	errorMsgExit(char *option, char *arg);

#endif