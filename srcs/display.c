#include "../incs/nmap.h"

/*
**  Display user manual if requested (--help), bad option or bad option value
*/
void    displayHelp(t_env *env, int code)
{
    printf("User manual:\n");
    printf("ft_nmap [OPTIONS]\n");
    printf("--help      Print user manual\n");
    printf("--ports     Port(s) to scan [min: 1 / max: 65535 / default: 1-1024] [max number of port: 1024] (eg: 1-10 or 80,443,8888 or 80-88,443)\n");
    printf("--ip        IP adress to scan [one adress accepted, for more targets see --file] (eg: 8.8.8.8 or scanme.nmap.org)\n");
    printf("--file      File containing a list of IP adresses to scan [one address per line]\n");
    printf("--speedup   Max number of parrallel threads to use [min: 0 / max: 250 / default: 0]\n");
    printf("--scan      Scan type(s) SYN/ACK/NULL/FIN/XMAS/UDP [defaut: all] (eg: SYN or SYN/ACK or FIN/UDP/SYN)\n");
    clearResources(env, NULL);
    exit(code);
}

/*
**  Display that the target is up
**  Mutex for multithreading issue
*/
int8_t  displayHostUp(t_env *env)
{
    pthread_mutex_lock(&env->display_lock);
    printf("Host: %s [%s] is up\n", env->target.list->s_ip, env->target.list->s_host);
    pthread_mutex_unlock(&env->display_lock);
    return (1);
}

/*
**  Display that the target is down
**  Mutex for multithreading issue
*/
int8_t  displayHostDown(t_env *env)
{
    pthread_mutex_lock(&env->display_lock);
    *env->stats.host_down += 1;
    printf("Host: %s [%s] seems down\n", env->target.list->s_ip, env->target.list->s_host);
    pthread_mutex_unlock(&env->display_lock);
    return (0);
}

/*
**  Display conclusion
*/
void    displayConclusion(t_env *env)
{
    env->stats.g_end = getTsMs();
    printf("ft_nmap done: %llu IP adress(es) (%llu host(s) up)", env->target.nb, (env->target.nb - *env->stats.host_down));
    printf(" scanned in %.1LF seconds\n", ((env->stats.g_end - env->stats.g_start) / 1000));
}

/*
**  Display scan type for introduction
*/
void    printScanType(uint8_t all_scans)
{
    uint8_t sep;

    sep = FALSE;
    for (uint8_t type = 1; type <= SUDP; type <<= 1) {
        if (all_scans & type) {
            if (sep)
                printf("/");
            switch (type) {
                case (SSYN):    sep = printf("SYN");    break;
                case (SACK):    sep = printf("ACK");    break;
                case (SNULL):   sep = printf("NULL");   break;
                case (SFIN):    sep = printf("FIN");    break;
                case (SXMAS):   sep = printf("XMAS");   break;
                case (SUDP):    sep = printf("UDP");    break;
            }
        }
    }
}

/*
**  Display introduction
*/
void    displayIntroduction(t_env *env)
{
    printf("Scan configurations\n");
    printf("Number of target(s): %llu\n", env->target.nb);
    printf("Number of port(s): %u\n", env->port.nb);
    printf("Number of thread(s): %u\n", *env->thread.nb);
    printf("Scan type(s): ");
    printScanType(env->scan.all);
    printf("\n\n");

}

/*
**  Return port state and set color accordingly
*/
char    *getPortState(uint16_t flag, uint8_t type)
{
    if (type == SACK) {
        switch (flag) {
            case (UNFILT):  printf("\033[38;5;99m");    break;
            case (FILT):    printf("\033[38;5;38m");    break;
        }
        switch (flag) {
            case (UNFILT):  return ("UNFILTERED\033[0m");
            case (FILT):    return ("FILTERED\033[0m");
        }
    }
    else {
        switch (flag) {
            case (OPEN):        printf("\033[38;5;40m");    break;
            case (FILT):        printf("\033[38;5;38m");    break;
            case (CLOSED):      printf("\033[38;5;196m");   break;
            case (OPEN_FILT):   printf("\033[38;5;202m");   break;
        }
        switch (flag) {
            case (OPEN):        return ("OPEN\033[0m");
            case (FILT):        return ("FILTERED\033[0m");
            case (CLOSED):      return ("CLOSED\033[0m");
            case (OPEN_FILT):   return ("OPEN|FILTERED\033[0m");
        }
    }
    return ("N/A");
}

/*
**  Display a certain number of space for alignment purpose 
*/
void    printSpace(uint8_t nspace)
{
    fflush(stdout);
    for (uint8_t pos = 0; pos < nspace; pos++)
        write(1, " ", 1);
}

/*
**  Display scan type and port state
*/
uint8_t printPortState(char *s_type, uint8_t nspace, uint16_t flag, uint8_t type)
{
    int32_t ret;

    if (nspace)
        printf("  | ");

    printf("%s [", s_type);
    ret = printf("%s", getPortState(flag, type));
    printf("]");

    switch (type) {
        case (SSYN):    printSpace(8 - (ret - 5));   break; 
        case (SACK):    printSpace(10 - (ret - 5));   break;
        case (SNULL):   printSpace(13 - (ret - 5));   break;
        case (SFIN):    printSpace(13 - (ret - 5));   break;
        case (SXMAS):   printSpace(13 - (ret - 5));   break;
        case (SUDP):    printSpace(13 - (ret - 5));   break;
    }
    return (TRUE);
}

/*
**  Display port number
*/
void    printPort(uint16_t port)
{
    uint8_t res;

    res = printf("%d", port);
    printSpace(5 - res);
}

/*
**  Display service
*/
void    printService(uint16_t port)
{
    struct servent  *service;
    uint8_t         res;

    service = getservbyport(htons(port), NULL);
    if (!(service)) {
        res = printf("unknown");
    }
    else if (strlen(service->s_name) > 16) {
        fflush(stdout);
        write(1, service->s_name, 15);
        write(1, ".", 1);
        res = 16;
    }
    else {
        res = printf("%s", service->s_name);
    }
    printSpace(16 - res);
}

/*
**  Verify for each scan type if requested by user
**  If it is, then call function to display port state
*/
void    displayPortState(uint8_t all_scans, t_result port_res)
{
    uint8_t sep;

    sep = FALSE;
    if (all_scans & SSYN)
        sep = printPortState("SYN", sep, port_res.syn, SSYN);
    if (all_scans & SACK)
        sep = printPortState("ACK", sep, port_res.ack, SACK);
    if (all_scans & SNULL)
        sep = printPortState("NULL", sep, port_res.null, SNULL);
    if (all_scans & SFIN)
        sep = printPortState("FIN", sep, port_res.fin, SFIN);
    if (all_scans & SXMAS)
        sep = printPortState("XMAS", sep, port_res.xmas, SXMAS);
    if (all_scans & SUDP)
        sep = printPortState("UDP", sep, port_res.udp, SUDP);
}

/*
**  Target informations
*/
void    printTargetInfo(t_env *env)
{
    printf("Target: %s [%s]\n", env->target.list->s_ip, env->target.list->s_host);
    printf("Scan duration: %.1LF seconds\n", ((env->stats.s_end - env->stats.s_start) / 1000));
    printf("\033[38;5;15mPORT  | SERVICE          | STATE\033[0m\n");
}

/*
**  Main function for displaying all information for a target scan
*/
void    displayResults(t_env *env)
{
    sortPort(env);
    printTargetInfo(env);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        printPort(env->port.list[pos]);
        printf(" | ");
        printService(env->port.list[pos]);
        printf(" | ");
        displayPortState(env->scan.all, env->port.result[pos]);
        printf("\n");
    }
    printf("\n");
}  