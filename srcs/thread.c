#include "../incs/nmap.h"

/*
**  Verify if at least 2 threads are avalaibles
*/
int8_t  isThreadAvailable(t_env *env)
{
    int8_t  res;

    pthread_mutex_lock(&env->thread.lock);
    res = (*(env->thread.nb) >= 2) ? TRUE : FALSE;
    pthread_mutex_unlock(&env->thread.lock);
    return (res);
}

/*
**  Decrement 2 threads from thread pool
*/
void    decrementThreadPool(t_env *env)
{
    pthread_mutex_lock(&env->thread.lock);
    *(env->thread.nb) -= 2;
    pthread_mutex_unlock(&env->thread.lock);
}

/*
**  Increment 2 threads from thread pool
*/
void    incrementThreadPool(t_env *env)
{
    pthread_mutex_lock(&env->thread.lock);
    *(env->thread.nb) += 2;
    pthread_mutex_unlock(&env->thread.lock);
}

/*
**  Set sniffer state for multithread communication and timing
*/
void    setSnifferState(t_env *env, uint8_t *sniffer, uint8_t state)
{
    pthread_mutex_lock(&env->sniffer.lock);
    *sniffer = state;
    pthread_mutex_unlock(&env->sniffer.lock);
}