#include "../incs/nmap.h"

int8_t displayHostUp(t_env *env)
{
    pthread_mutex_lock(&env->display_lock);
    printf("Host: %s [%s] is up\n", env->l_target->s_ip, env->l_target->s_host);
    pthread_mutex_unlock(&env->display_lock);
    return (1);
}

int8_t displayHostDown(t_env *env)
{
    pthread_mutex_lock(&env->display_lock);
    printf("Host: %s [%s] seems down\n", env->l_target->s_ip, env->l_target->s_host);
    pthread_mutex_unlock(&env->display_lock);
    return (0);
}

void displayGLobalDuration(t_env *env)
{
    env->stats.g_end = get_ts_ms();
    printf("Global duration: %.1LF secs\n", ((env->stats.g_end - env->stats.g_start) / 1000));
}

char *getPortState(uint16_t flag, uint8_t type)
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

void printSpace(uint8_t nspace)
{
    fflush(stdout);
    for (uint8_t pos = 0; pos < nspace; pos++)
        write(1, " ", 1);
}

uint8_t displayScanType(char *s_type, uint8_t nspace, uint16_t flag, uint8_t type)
{
    int ret;

    if (nspace)
        printf("  |  ");

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

void sortPort(t_env *env)
{
    uint16_t    tmp_port;
    t_result    tmp_res;
    uint16_t    s_pos;

    s_pos = 0;
    for (uint16_t a_pos = 0; a_pos < env->port.nb; a_pos++) {
        for (uint16_t f_pos = 0; f_pos < (env->port.nb - 1); f_pos++) {
            s_pos = f_pos + 1;
            if (env->port.list[f_pos] > env->port.list[s_pos]) {
                tmp_port = env->port.list[f_pos];
                env->port.list[f_pos] = env->port.list[s_pos];
                env->port.list[s_pos] = tmp_port;

                tmp_res = env->port.result[f_pos];
                env->port.result[f_pos] = env->port.result[s_pos];
                env->port.result[s_pos] = tmp_res;
            }
        }
    }
}

void printPort(uint16_t port)
{
    uint8_t res;

    res = printf("%d", port);
    printSpace(5 - res);
}

void printService(uint16_t port)
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

void printPortState(uint8_t all_scans, t_result port_res)
{
    uint8_t     sep;

    sep = FALSE;
    if (all_scans & SSYN)
        sep = displayScanType("SYN", sep, port_res.syn, SSYN);
    if (all_scans & SACK)
        sep = displayScanType("ACK", sep, port_res.ack, SACK);
    if (all_scans & SNULL)
        sep = displayScanType("NULL", sep, port_res.null, SNULL);
    if (all_scans & SFIN)
        sep = displayScanType("FIN", sep, port_res.fin, SFIN);
    if (all_scans & SXMAS)
        sep = displayScanType("XMAS", sep, port_res.xmas, SXMAS);
    if (all_scans & SUDP)
        sep = displayScanType("UDP", sep, port_res.udp, SUDP);
}

void printTargetInfo(t_env *env)
{
    printf("Target: %s [%s]\n", env->l_target->s_ip, env->l_target->s_host);
    printf("Scan duration: %.1LF secs\n", ((env->stats.s_end - env->stats.s_start) / 1000));
    printf("\033[38;5;15mPORTS | SERVICES         | RESULTS\033[0m\n");
}

void displayResults(t_env *env)
{
    sortPort(env);


    printTargetInfo(env);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        printPort(env->port.list[pos]);
        printf(" | ");
        printService(env->port.list[pos]);
        printf(" | ");
        printPortState(env->scan.all, env->port.result[pos]);
        printf("\n");
    }
    printf("\n");
}  