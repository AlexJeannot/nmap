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

void sendDatagramByThread(t_probe_info info)
{
    pthread_t   id;

    info.is_thread = TRUE;
    if (pthread_create(&id, NULL, sendDatagram, (void *)&info))
        errorMsgExit("sender thread creation", "UDP datagram");
}

void sendSegmentByThread(t_probe_info info)
{
    pthread_t   id;
    t_probe_info *info2;

    info2 = malloc(sizeof(t_probe_info));
    memcpy(info2, &info, sizeof(t_probe_info));
    info2->is_thread = TRUE;
    printf("sendSegmentByThread info.port = %d\n", info2->port);
    if (pthread_create(&id, NULL, sendSegment, (void *)info2))
        errorMsgExit("sender thread creation", "TCP segment");
}