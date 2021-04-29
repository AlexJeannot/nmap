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

/*
**  Wait for sniffer to be ready
**  While sniffer is not ready
**  -- Check variable
**  -- Sleep 100ms
*/
void waitForSniffer(t_env *env)
{
    while (1) {
        pthread_mutex_lock(&env->sniffer.lock);
        if (env->sniffer.ready) {
            pthread_mutex_unlock(&env->sniffer.lock);
            break;
        }
        pthread_mutex_unlock(&env->sniffer.lock);
        usleep(100000);
    }
}

/*
**  Wait for sniffer to finish
**  While sniffer is not finished
**  -- Check variable
**  -- Sleep 100ms
*/
void waitForEndSniffer(t_env *env)
{
    while (1) {
        pthread_mutex_lock(&env->sniffer.lock);
        if (env->sniffer.end) {
            pthread_mutex_unlock(&env->sniffer.lock);
            break;
        }
        pthread_mutex_unlock(&env->sniffer.lock);
        usleep(100000);
    }
}

/*
**  Wait for response after all probes sent
**  Wait 1000ms
**  -- Check variable
**  -- Breakloop sniffer
**  -- Wait for sniffer to finish
*/
void waitForReponse(t_env *env)
{
    usleep(1000000);
    pcap_breakloop(env->target.list->s_handle);
    waitForEndSniffer(env);
}

/*
**  Wait for all thread started
**  Join each thread from the id array
*/
void waitForSender(pthread_t *ids, uint64_t target_nb)
{
    for (uint64_t pos = 0; pos < target_nb; pos++) {
        pthread_join(ids[pos], NULL);
    }
}