#include "../incs/nmap.h"

/*
**  Signal handler for SIGINT and SIGQUIT
**  Clear resources allocated if signal detected and then exit here
*/
void signalHandler(int code)
{
    if (code == SIGINT || code == SIGQUIT) {
        printf("\b\bft_nmap: program exit due to signal\n");
	    clearResources(sig_env, NULL);
        exit(0);
    }
}

/*
**  Set signal handler for SIGINT and SIGQUIT
*/
void setSignalHandler(t_env *env)
{
    struct sigaction sig_action;

    sig_action.__sigaction_u.__sa_handler = signalHandler;
    if (sigaction(SIGINT, &sig_action, NULL) == -1)
        errorMsgExit(env, "signal settings", "SIGINT handler");
    if (sigaction(SIGQUIT, &sig_action, NULL) == -1)
        errorMsgExit(env, "signal settings", "SIGQUIT handler");
}