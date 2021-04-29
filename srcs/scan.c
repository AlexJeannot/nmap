#include "../incs/nmap.h"

/*
**  Function in charge of scanning target (second step of scan)
**  Get start timestamp for stats
**  For each scan type (SYN/ACK/FIN/NULL/XMAS/UDP)
**  If scan type requested by user
**  -- Set scan type as current
**  -- Set sniffer state as not ready and not finished
**  -- Create sniffer thread
**  -- Wait for sniffer thread to be ready
**  -- Send all TCP segment or UDP datagram depending on scan type
**  -- Wait for reply from target
**  Get end timestamp for stats
*/
void scanTarget(t_env *env)
{
    env->stats.s_start = get_ts_ms();
    for (uint8_t type = 1; type <= SUDP; type <<= 1) {
        if (env->scan.all & type) {

            env->scan.current = type;
            setSnifferState(env, &env->sniffer.ready, FALSE);
            setSnifferState(env, &env->sniffer.end, FALSE);
            if (pthread_create(&env->sniffer.id, NULL, packetSniffer, (void *)env))
                errorMsgExit(env, "sniffer thread creation", "TCP scan");
            waitForSniffer(env);

            (type == SUDP) ? sendDatagram(env) : sendSegment(env);
            waitForReponse(env);
        }
    }
    env->stats.s_end = get_ts_ms();
}

/*
**  Generic function usable in multithreading environment or not
**  Ping target
**  If host is up
**  -- Scan target
**  If multithreading
**  -- Increment thread available by 2
*/
void *execScan(void *input)
{
    t_env *env;

    env = (t_env *)input;
    if (pingTarget(env))
        scanTarget(env);
    if (env->thread.on)
        incrementThreadPool(env);

    return ((void*)0);
}