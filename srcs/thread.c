#include "../incs/nmap.h"

int8_t  isThreadAvailable(t_env *env)
{
    int8_t  res;
    pthread_mutex_lock(&env->thread.lock);
    res = (env->thread.nb > 0) ? TRUE : FALSE;
    if (!(res))
        pthread_mutex_unlock(&env->thread.lock);
    return (res);
}

void decrementThreadPool(t_env *env)
{
    env->thread.nb--;
    pthread_mutex_unlock(&env->thread.lock);
}

void incrementThreadPool(t_env *env)
{
    pthread_mutex_lock(&env->thread.lock);
    env->thread.nb++;
    pthread_mutex_unlock(&env->thread.lock);
}