#include "../incs/nmap.h"




uint8_t waitForResponse(t_env *env, uint16_t ms)
{
    struct timeval start;
    struct timeval check;
    struct timezone tz;

    bzero(&start, sizeof(start));
    bzero(&check, sizeof(check));

    gettimeofday(&start, &tz);
    while ((!(env->ping.imcp_r) && !(env->ping.tcp_r)) || ((check.tv_sec * 1000) - (start.tv_sec * 1000)) < ms) {
        // printf("((check.tv_sec * 1000) - (start.tv_sec * 1000)) = %ld\n", ((check.tv_sec * 1000) - (start.tv_sec * 1000)));
        gettimeofday(&check, &tz);
    }
    if (((check.tv_sec * 1000) - (start.tv_sec * 1000)) < ms) {
        return (FALSE);
    }
    return (TRUE);
}

/*
 * Get time is millisecond
*/
long double	get_ts_ms(void)
{
	struct	timeval tv;
	struct	timezone tz;

	gettimeofday(&tv, &tz);
	return (((long double)tv.tv_sec * 1000) + ((long double)tv.tv_usec / 1000));
}

void waitForEndSniffer(t_env *env)
{
    while (1) {
        pthread_mutex_lock(&env->sniffer_lock);
        if (env->sniffer_end) {
            pthread_mutex_unlock(&env->sniffer_lock);
            break;
        }
        pthread_mutex_unlock(&env->sniffer_lock);
        usleep(100000);
    }
}

// void waitForReponse(pthread_t id)
void waitForReponse(t_env *env)
{
    (void)env;
    printf("BEFORE USPLEEP\n");
    usleep(1500000);
    printf("BEFORE BREAKLOOP SCAN\n");
    pcap_breakloop(env->l_target->s_handle);
    waitForEndSniffer(env);
}

void waitForPingReponse(t_env *env)
{
    usleep(1000000);
    printf("BEFORE BREAKLOOP PING\n");
    pcap_breakloop(env->l_target->p_handle);
    waitForEndSniffer(env);
}

void waitForReponse_thread(t_env *main_env, t_env *all_env)
{
    usleep(1500000);
    for (uint64_t pos = 0; pos < main_env->nb_target; pos++)
        pthread_cancel(all_env[pos].sniffer_id);
}

void waitForSender(pthread_t *ids, uint64_t target_nb)
{
    for (uint64_t pos = 0; pos < target_nb; pos++) {
        printf("WAIT FOR POS %llu\n", pos);
        pthread_join(ids[pos], NULL);
    }
    printf("END WAIT FOR\n");
}

void waitForSniffer(t_env *env)
{
    while (1) {
        pthread_mutex_lock(&env->sniffer_lock);
        if (env->sniffer_ready) {
            pthread_mutex_unlock(&env->sniffer_lock);
            break;
        }
        pthread_mutex_unlock(&env->sniffer_lock);
        usleep(100000);
    }
}

int8_t pingTarget(t_env *env)
{
    struct icmp icmp_header;
    struct tcphdr  tcp_header;
    // t_probe_info    info;

    setHeader_ICMP(&icmp_header);

    // setProbeInfo(env, &info, SSYN);
    // setProbePort(&info, 80);
    setHeader_TCP(env, &tcp_header, 80);
    setTargetPort(&env->l_target->n_ip, 80);

    printf("[PING] target port = %d\n", ntohs(((struct sockaddr_in *)&env->l_target->n_ip)->sin_port));


    env->scan.current = SPING;
    printf("BEFORE SNIFFER THREAD CREATION PING\n");
    if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
        errorMsgExit("sniffer thread creation", "ping");

    waitForSniffer(env);
    printf("AFTER TIMER SENDER\n");
    env->ping.ts_start = get_ts_ms();
    if (sendto(env->sock.icmp, &icmp_header, sizeof(struct icmp), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "ICMP ping");

    if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "TCP ping");

    // waitForPingReponse(env);
    pthread_join(env->sniffer_id, NULL);
    if (env->ping.imcp_r || env->ping.tcp_r)
        printf("\033[38;5;40m-> %s is UP\n\033[0m", env->l_target->s_host);
    else
        printf("\033[38;5;160m-> %s is DOWN\nicmp = %d\ntcp = %d\n\033[0m", env->l_target->s_host, env->ping.imcp_r, env->ping.tcp_r);

    return ((isHostUp(env)) ? displayHostUp(env) : displayHostDown(env));
}


void scanTarget(t_env *env)
{
    for (uint8_t type = 1; type <= SUDP ; type <<= 1) {
        if (env->scan.all & type) {
            printf("\n-------------------------\n");
            env->scan.current = type;
            printf("BEFORE SNIFFER THREAD CREATION SCAN\n");

            pthread_mutex_lock(&env->sniffer_lock);
            env->sniffer_ready = FALSE;
            env->sniffer_end = FALSE;
            pthread_mutex_unlock(&env->sniffer_lock);

            if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
                errorMsgExit("sniffer thread creation", "TCP scan");
            
            waitForSniffer(env);
            (type == SUDP) ? sendDatagram(env) : sendSegment(env);
        }
    }
}
void *execScan(void *input)
{
    t_env *env;

    env = (t_env *)input;

    // pthread_mutex_init(&env->ping.lock, NULL);
    pthread_mutex_lock(&env->sniffer_lock);
    env->sniffer_ready = FALSE;
    env->sniffer_end = FALSE;
    pthread_mutex_unlock(&env->sniffer_lock);
    
    if (pingTarget(env)) {
        printf("\n############################# SCAN #############################\n");
        scanTarget(env);
        waitForReponse(env);
        // displayResults(env);
    }

    if (env->thread.on)
        incrementThreadPool(env);
    return ((void*)0);
}

void execWithoutThreads(t_env *env, t_target *all_target)
{
    pthread_mutex_init(&env->sniffer_lock, NULL);

    env->l_target = all_target;
    while (env->l_target) {
        execScan(env);
        // waitForReponse(env->sniffer_id);
        // waitForReponse(env);
        if (isHostUp(env))
            displayResults(env);

        env->ping.imcp_r = 0;
        env->ping.tcp_r = 0;
        env->ping.ts_start = 0;
        env->ping.ts_end = 0;

        for (uint16_t pos = 0; pos < env->port.nb; pos++) { // Create FUNCTION
            env->port.result[pos].syn = FILT;
            env->port.result[pos].ack = FILT;
            env->port.result[pos].null = OPEN_FILT;
            env->port.result[pos].fin = OPEN_FILT;
            env->port.result[pos].xmas = OPEN_FILT;
            env->port.result[pos].udp = OPEN_FILT;
        }

        env->l_target = env->l_target->next;
    }
    env->l_target = all_target;
    // displayResults(env);
}

void execWithThreads(t_env *main_env, t_target *all_target)
{
    printf("main_env->nb_target = %llu\n", main_env->nb_target);
    t_env   env[main_env->nb_target];
    pthread_t id[main_env->nb_target];
    t_target    *tmp;

    bzero(&env[0], (sizeof(t_env) * main_env->nb_target));
    printf("ENTREE MULTI TREHAD\n");
    tmp = all_target;
    for (uint64_t pos = 0; tmp != NULL; pos++) {
        printf("pos lal = %llu\n", pos);
        if (isThreadAvailable(main_env)) {
            printf("POST VERIF THREAD\n");
            printf("&env[pos] = %p\n", &env[pos]);
            memcpy(&env[pos], main_env, sizeof(t_env));
            printf("POST memcpy pos = %llu\n", pos);
            env[pos].l_target = tmp;
            decrementThreadPool(env);
            if (pthread_create(&id[pos], NULL, execScan, (void *)&env[pos]))
                errorMsgExit("target thread creation", "scan");
            tmp = tmp->next;
            printf("all_target post nrxt = %p\n", tmp);
        }
        else {
            pthread_join(id[pos - 1], NULL);
            pos--;
        }
    }
    waitForSender(&id[0], env->nb_target);
    // waitForReponse_thread(main_env, &env[0]);
    for (uint64_t pos = 0; pos < main_env->nb_target; pos++) {
        if (isHostUp(&env[pos]))
            displayResults(&env[pos]);
    }
    // displayResults(&env[0]);
    // displayResults(&env[1]);

}


int main(int argc, char **argv)
{
    t_env env;
    t_target *all_target;

    bzero(&env, sizeof(env));
    all_target = NULL;
    bzero(&siginfo, sizeof(siginfo));
    parseArgs(&env, &all_target, argc, argv);
    printf("RETOUR MAIN\n");
    getSourceIP(&env);
    createSocket(&env);

    pthread_mutex_init(&env.thread.lock, NULL);

    if (env.thread.on)
        execWithThreads(&env, all_target);
    else
        execWithoutThreads(&env, all_target);

    return (0);
}