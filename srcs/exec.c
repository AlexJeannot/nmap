#include "../incs/nmap.h"

/*
**  Exec actions for all targets if no thread requested
**  While there is a target
**  -- Execute scan
**  -- If host is up
**  --- Display Result
**  -- Clean ping result for next target
**  -- Clean port state for next target
*/
void    execWithoutThreads(t_env *env)
{
    while (env->target.list) {
        execScan(env);
        if (isHostUp(env))
            displayResults(env);

        bzero(&env->ping, sizeof(t_ping));
        setDefaultPortState(env);
        env->target.list = env->target.list->next;
    }
}

/*
**  Exec actions for all targets if threads requested
**  Create an env array of target number size
**  Create an pthread_t array of target number size
**  While there is a target
**  -- If threads available (2)
**  --- Copy information from main env
**  --- Set target pointer to current target
**  --- Decrement thread number by 2
**  --- Create thread to execute scan
**  -- Else
**  --- Wait for last thread to finish
**  Wait for all threads to finish
**  For all targets
**  -- If target is up
**  --- Display results
*/
void    execWithThreads(t_env *main_env)
{

    t_env           env[main_env->target.nb];
    pthread_t       id[main_env->target.nb];
    t_list_target   *tmp;

    bzero(&env[0], (sizeof(t_env) * main_env->target.nb));
    tmp = main_env->target.start;
    for (uint64_t pos = 0; tmp != NULL; tmp = tmp->next) {
        if (isThreadAvailable(main_env)) {
            memcpy(&env[pos], main_env, sizeof(t_env));
            env[pos].target.list = tmp;
            decrementThreadPool(env);
            if (pthread_create(&id[pos], NULL, execScan, (void *)&env[pos]))
                errorMsgExit(main_env, "target thread creation", "scan");
            pos++;
        }
        else {
            pthread_join(id[pos - 1], NULL);
        }
    }
    waitForSender(&id[0], env->target.nb);

    printf("\n");
    for (uint64_t pos = 0; pos < main_env->target.nb; pos++) {
        if (isHostUp(&env[pos]))
            displayResults(&env[pos]);
    }
}