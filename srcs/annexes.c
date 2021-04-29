#include "../incs/nmap.h"

/*
**  Set the scan result if no response from target
**  For each port provided
*/
void setDefaultPortState(t_env *env)
{
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        env->port.result[pos].syn = FILT;
        env->port.result[pos].ack = FILT;
        env->port.result[pos].null = OPEN_FILT;
        env->port.result[pos].fin = OPEN_FILT;
        env->port.result[pos].xmas = OPEN_FILT;
        env->port.result[pos].udp = OPEN_FILT;
    }
}

/*
**  Init variables as first step of the program
**  Number of host down must be on the heap because could be shared between threads
**  Init mutex to access thread information (number/incrementation/decrementation)
**  Init mutex to display ping result
**  Init mutex to orchestrate thread communication and timing
**  Save pointer to env structure because may need it for freeing resources if error exit in a thread
*/
void initProgram(t_env *env)
{
    bzero(env, sizeof(t_env));
    env->main_env = env;
    env->stats.g_start = get_ts_ms();
    setDefaultPortState(env);
    
    if (!(env->stats.host_down = (uint64_t *)malloc(sizeof(uint64_t))))
        errorMsgExit(env, "malloc [Stats allocation]", "host down");
    bzero(env->stats.host_down, sizeof(uint64_t));

    pthread_mutex_init(&env->thread.lock, NULL);
    pthread_mutex_init(&env->display_lock, NULL);
    pthread_mutex_init(&env->sniffer.lock, NULL);
}

/*
**  Verify and set default parameters after parsing arguments
**  Exit if no target provided (only mandatory argument)
**  If no port range provided then 1-1024
**  If no scan type provided then all
*/
void setDefautParams(t_env *env)
{
    if (!(env->target.list))
        errorMsgExit(env, "ip address or hostname", "no target provided");
    env->target.start = env->target.list;

    if (env->port.nb == 0)
        addPortRange(env, "default", 1, 1024);

    if (env->scan.all == 0)
        parseScan(env, "SYN/ACK/NULL/FIN/XMAS/UDP");

    if (env->thread.nb && isThreadAvailable(env))
        env->thread.on = TRUE;
}

/*
**  Sort port by number
**  Must sort result accordingly
*/
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