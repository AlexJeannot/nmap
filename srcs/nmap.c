#include "../incs/nmap.h"



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
    // printf("BEFORE USPLEEP\n");
    usleep(1500000);
    // printf("BEFORE BREAKLOOP SCAN\n");
    pcap_breakloop(env->l_target->s_handle);
    waitForEndSniffer(env);
}

void waitForPingReponse(t_env *env)
{
    usleep(1000000);
    // printf("BEFORE BREAKLOOP PING\n");
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
        // printf("WAIT FOR POS %llu\n", pos);
        pthread_join(ids[pos], NULL);
    }
    // printf("END WAIT FOR\n");
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


    setHeader_ICMP(&icmp_header);
    setHeader_TCP(env, &tcp_header, 80);
    setTargetPort(&env->l_target->n_ip, 80);

    env->scan.current = SPING;
    setSnifferState(env, &env->sniffer_ready, FALSE);
    setSnifferState(env, &env->sniffer_end, FALSE);
    if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
        errorMsgExit("sniffer thread creation", "ping");
    waitForSniffer(env);

    if (sendto(env->sock.icmp, &icmp_header, sizeof(struct icmp), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "ICMP ping");
    if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "TCP ping");

    pthread_join(env->sniffer_id, NULL);
    return ((isHostUp(env)) ? displayHostUp(env) : displayHostDown(env));
}

void scanTarget(t_env *env)
{
    env->stats.s_start = get_ts_ms();
    for (uint8_t type = 1; type <= SUDP; type <<= 1) {
        if (env->scan.all & type) {

            env->scan.current = type;
            setSnifferState(env, &env->sniffer_ready, FALSE);
            setSnifferState(env, &env->sniffer_end, FALSE);
            if (pthread_create(&env->sniffer_id, NULL, packetSniffer, (void *)env))
                errorMsgExit("sniffer thread creation", "TCP scan");
            waitForSniffer(env);

            (type == SUDP) ? sendDatagram(env) : sendSegment(env);
            waitForReponse(env);
        }
    }
    env->stats.s_end = get_ts_ms();
}

void *execScan(void *input)
{
    t_env *env;

    env = (t_env *)input;

    if (pingTarget(env)) {
        scanTarget(env);
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

        if (isHostUp(env))
            displayResults(env);

        env->ping.imcp_r = 0;
        env->ping.tcp_r = 0;

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
}

void execWithThreads(t_env *main_env, t_target *all_target)
{

    t_env   env[main_env->nb_target];
    pthread_t id[main_env->nb_target];
    t_target    *tmp;

    bzero(&env[0], (sizeof(t_env) * main_env->nb_target));
    pthread_mutex_init(&main_env->display_lock, NULL);
    // printf("ENTREE MULTI TREHAD\n");
    tmp = all_target;
    for (uint64_t pos = 0; tmp != NULL; pos++) {
        // printf("pos lal = %llu\n", pos);
        if (isThreadAvailable(main_env)) {
            // printf("POST VERIF THREAD\n");
            // printf("&env[pos] = %p\n", &env[pos]);
            memcpy(&env[pos], main_env, sizeof(t_env));
            // printf("POST memcpy pos = %llu\n", pos);
            env[pos].l_target = tmp;
            decrementThreadPool(env);
            if (pthread_create(&id[pos], NULL, execScan, (void *)&env[pos]))
                errorMsgExit("target thread creation", "scan");
            tmp = tmp->next;
            // printf("all_target post nrxt = %p\n", tmp);
        }
        else {
            pthread_join(id[pos - 1], NULL);
            pos--;
        }
    }
    waitForSender(&id[0], env->nb_target);

    printf("\n");
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
    env.stats.g_start = get_ts_ms();
    parseArgs(&env, &all_target, argc, argv);
    getSourceIP(&env);
    createSocket(&env);

    pthread_mutex_init(&env.thread.lock, NULL);

    if (env.thread.on)
        execWithThreads(&env, all_target);
    else
        execWithoutThreads(&env, all_target);

    displayGLobalDuration(&env);
    return (0);
}