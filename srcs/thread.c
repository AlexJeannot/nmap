#include "../incs/nmap.h"

int8_t  isThreadAvailable(t_env *env)
{
    int8_t  res;

    pthread_mutex_lock(&env->thread.lock);
    // printf("(env->thread.nb) = %p\n", (env->thread.nb));
    // printf("*(env->thread.nb) = %d\n", *(env->thread.nb));
    // printf("(env->thread.nb) = %p\n", (env->thread.nb));
    res = (*(env->thread.nb) >= 2) ? TRUE : FALSE;
    pthread_mutex_unlock(&env->thread.lock);
    return (res);
}

void decrementThreadPool(t_env *env)
{
    pthread_mutex_lock(&env->thread.lock);
    *(env->thread.nb) -= 2;
    pthread_mutex_unlock(&env->thread.lock);
}

void incrementThreadPool(t_env *env)
{
    pthread_mutex_lock(&env->thread.lock);
    *(env->thread.nb) += 2;
    pthread_mutex_unlock(&env->thread.lock);
}