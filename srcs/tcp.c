#include "../incs/nmap.h"

void setHeader_TCP(t_env *env, struct tcphdr *header, uint16_t port)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->l_target->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_TCP;
    chk.length = htons((uint16_t)sizeof(struct tcphdr));

    bzero(header, sizeof(struct tcphdr));
    header->th_sport = htons(44380);
    header->th_dport = htons(port);
    header->th_seq = 0; // TODO
    header->th_ack = 0;
    header->th_off = 5;
    header->th_win =  htons(1024);
    header->th_urp = 0;

    switch (env->scan.current) {
        case (SSYN):   header->th_flags = TH_SYN;                      break;
        case (SPING):   header->th_flags = TH_SYN;                      break;
        case (SACK):            header->th_flags = TH_ACK;                      break;
        case (SNULL):           header->th_flags = 0;                           break;
        case (SFIN):            header->th_flags = TH_FIN;                      break;
        case (SXMAS):           header->th_flags = TH_FIN | TH_PUSH | TH_URG;   break;
    }

    memcpy(&chk.hdr.tcp, header, sizeof(struct tcphdr));
    header->th_sum = calcul_checksum(&chk, sizeof(struct tcphdr) + CHKSM_PREHDR_LEN);
}

// void sendSegment(t_env *env, uint16_t port)
// {
//     struct tcphdr tcp_header;

//     setHeader_TCP(env, &tcp_header, port);
//     setTargetPort(&env->l_target->n_ip, port);

//     if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
//         errorMsgExit("sendto() call", "TCP scan");
// }

// void *sendSegment_Thread(void *input)
// {
//     t_env           *env;
//     struct tcphdr   tcp_header;
//     struct sockaddr target;
//     int16_t         index;
    
//     env = (t_env *)input;
//     memcpy(&target, &env->l_target->n_ip, sizeof(struct sockaddr));
//     while (1) {
//         if ((index = setPortIndex(env)) == -1) {
//             incrementThreadPool(env);
//             pthread_exit((void *)0);
//         }

//         setTargetPort(&target, env->port.list[index]);
//         setHeader_TCP(env, &tcp_header, env->port.list[index]);

//         if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &target, sizeof(struct sockaddr)) < 0)
//             errorMsgExit("sendto() call", "TCP scan");
//     }
// }

// void sendAllSegment(t_env *env)
// {
//     long double bef;
//     long double after;
//     pthread_t id;
//     // int32_t count = 0;


//     bef = get_ts_ms();
//     if (env->thread.on) {
//         while (getPortIndex(env) && isThreadAvailable(env)) {
//             decrementThreadPool(env);
//             if (pthread_create(&id, NULL, sendSegment_Thread, (void *)env))
//                 errorMsgExit("sender thread creation", "TCP segment");
//         }
//     }
//     else {
//         for (uint16_t pos = 0; pos < env->port.nb; pos++)
//             sendSegment(env, env->port.list[pos]);
//     }

//     after = get_ts_ms();
//     printf("TIME = %LF ms\n", (after - bef));
// }

void sendSegment(t_env *env)
{
    struct tcphdr tcp_header;
    long double bef;
    long double after;

    bef = get_ts_ms();
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        setHeader_TCP(env, &tcp_header, env->port.list[pos]);
        setTargetPort(&env->l_target->n_ip, env->port.list[pos]);

        if (sendto(env->sock.tcp, &tcp_header, sizeof(struct tcphdr), 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
            errorMsgExit("sendto() call", "TCP scan");
    }
    after = get_ts_ms();
    printf("TIME = %LF ms\n", (after - bef));
}