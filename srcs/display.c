#include "../incs/nmap.h"

int8_t displayHostUp(const t_env *env)
{
    printf("Host: %s [%s] is up (%LF ms)\n", env->l_target->s_ip, env->l_target->s_host, (env->ping.ts_end - env->ping.ts_start));
    return (1);
}

int8_t displayHostDown(const t_env *env)
{
    printf("Host: %s [%s] seems down\n", env->l_target->s_ip, env->l_target->s_host);
    return (0);
}

char *getPortState(uint16_t flag, uint8_t type)
{
    if (type == SACK) {
        switch (flag) {
            case (UNFILT):  return ("UNFILTERED");
            case (FILT):    return ("FILTERED");
        }
    }
    switch (flag) {
        case (OPEN):        return ("OPEN");
        case (FILT):        return ("FILTERED");
        case (CLOSED):      return ("CLOSED");
        case (OPEN_FILT):   return ("OPEN|FILTERED");
    }
    return ("N/A");
}

uint8_t displayScanType(char *s_type, uint8_t nspace, uint16_t flag, uint8_t type)
{
    if (nspace)
        printf("   |   ");
    printf("%s [%s]", s_type, getPortState(flag, type));
    return (TRUE);
}

void displayResults(const t_env *env)
{
    uint8_t     nspace;

    printf("\n++++++++++++++++++++++++++++++ PORTS ++++++++++++++++++++++++++++++\n");
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        nspace = FALSE;
        printf("Port %d: ", env->port.list[pos]);
        if (env->scan.all & SSYN)
            nspace = displayScanType("SYN", nspace, env->port.result[pos].syn, SSYN);
        if (env->scan.all & SACK)
            nspace = displayScanType("ACK", nspace, env->port.result[pos].ack, SACK);
        if (env->scan.all & SNULL)
            nspace = displayScanType("NULL", nspace, env->port.result[pos].null, SNULL);
        if (env->scan.all & SFIN)
            nspace = displayScanType("FIN", nspace, env->port.result[pos].fin, SFIN);
        if (env->scan.all & SXMAS)
            nspace = displayScanType("XMAS", nspace, env->port.result[pos].xmas, SXMAS);
        if (env->scan.all & SUDP)
            nspace = displayScanType("UDP", nspace, env->port.result[pos].udp, SUDP);
        printf("\n");
    }
}