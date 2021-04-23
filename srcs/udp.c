#include "../incs/nmap.h"

void setHeader_UDP(t_env *env, struct udphdr *hdr, uint16_t port)
{
    t_checksum chk;

    bzero(&chk, sizeof(t_checksum));
    memcpy(&chk.s_addr, &env->intf.n_ip, sizeof(in_addr_t));
    memcpy(&chk.t_addr, &env->l_target->ip, sizeof(in_addr_t));
    chk.type = IPPROTO_UDP;
    chk.length = htons((uint16_t)sizeof(struct udphdr)+ 14);

    bzero(hdr, sizeof(struct udphdr));
    hdr->uh_dport = htons(port);
    hdr->uh_sport = htons(44380);
    hdr->uh_ulen = htons(22);

    memcpy(&chk.hdr.udp, hdr, sizeof(struct udphdr));
    hdr->uh_sum = calcul_checksum(&chk, sizeof(struct udphdr) + CHKSM_PREHDR_LEN);
}

void sendDatagram(t_env *env, uint16_t port)
{
    struct udphdr udp_hdr;
    char data[22];

    setTargetPort(&env->l_target->n_ip, port);
    setHeader_UDP(env, &udp_hdr, port);
    printf("[%d] CHECKSUM = %x\n", port, udp_hdr.uh_sum);


    bzero(&data[0], 22);
    memcpy(&data[0], &udp_hdr, sizeof(struct udphdr));
    if (sendto(env->sock.udp, &data, 22, 0, &env->l_target->n_ip, sizeof(struct sockaddr)) < 0)
        errorMsgExit("sendto() call", "UDP scan");
}

void *sendDatagram_Thread(void *input)
{
    struct udphdr udp_hdr;
    char data[22];
    struct sockaddr target;
    int16_t         index;
    t_env           *env;

    env = (t_env *)input;
    memcpy(&target, &env->l_target->n_ip, sizeof(struct sockaddr));

    while (1) {
        if ((index = setPortIndex(env)) == -1) {
            incrementThreadPool(env);
            pthread_exit((void *)0);
        }

        setTargetPort(&target, env->port.list[index]);
        setHeader_UDP(env, &udp_hdr, env->port.list[index]);

        bzero(&data[0], 22);
        memcpy(&data[0], &udp_hdr, sizeof(struct udphdr));

        if (sendto(env->sock.udp, &data, 22, 0, &target, sizeof(struct sockaddr)) < 0)
            errorMsgExit("sendto() call", "UDP scan");
    }
}

void sendAllDatagram(t_env *env)
{
    long double bef;
    long double after;
    pthread_t id;

    bef = get_ts_ms();
    if (env->thread.on) {
        while (getPortIndex(env) && isThreadAvailable(env)) {
            decrementThreadPool(env);
            if (pthread_create(&id, NULL, sendDatagram_Thread, (void *)env))
                errorMsgExit("sender thread creation", "TCP segment");
        }
    }
    else {
        for (uint16_t pos = 0; pos < env->port.nb; pos++) {

            sendDatagram(env, env->port.list[pos]);
            if (pos && pos % 5 == 0)
                usleep(1000001);
        }
    }

    after = get_ts_ms();
    printf("TIME = %LF ms\n", (after - bef));
}