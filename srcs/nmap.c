#include "../incs/nmap.h"







void pingTarget(t_env *env)
{
    struct icmp icmp_p;
    struct tcphdr  tcp_p;
    int sock_icmp, sock_tcp;

    if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        errorMsgExit("ICMP socket", "ping socket() call failed");
    if ((sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        errorMsgExit("ICMP socket", "ping socket() call failed");

    bzero(&icmp_p, sizeof(struct icmp));
    bzero(&tcp_p, sizeof(struct tcphdr));

    icmp_p.icmp_type = 8;
    icmp_p.icmp_code = 0;

    


    icmp_p.icmp_cksum = 0;

}

int main(int argc, char **argv)
{
    t_env env;

    bzero(&env, sizeof(env));
    parseArgs(&env, argc, argv);
    while (env->l_target) {
        pingTarget(&env);


        env->l_target = env->l_target->next;
    }
}