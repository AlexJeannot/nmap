#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct s_env
{
    char test[5];
}       t_env;

void sighandler(int signal, siginfo_t* siginfo, void *elem)
{
    printf("signal = %d\n", signal);
    printf("SIGALRM = %d\n", SIGALRM);
    t_env *env = (t_env *)elem;
    printf("env->test = %s\n", env->test);
    printf("si_signo = %d\n", siginfo->si_signo);
    printf("si_code = %d\n", siginfo->si_code);
    printf("si_pid = %d\n", siginfo->si_pid);
}

int main()
{
    struct sigaction sig_action;
    // struct siginfo_t sig_info;
    t_env env;

    strcpy(env.test, "LALA");
    printf("START\n");

    sig_action.__sigaction_u.__sa_sigaction = sighandler;
    if (sigaction(SIGALRM, &sig_action, NULL) == -1) {
        printf("SIGACTION FAILED\n");
        exit(1);
    }

    alarm(1);

    sleep(4);

    printf("END\n");
}