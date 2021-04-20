#include "../incs/nmap.h"

void displayHelp(int i)
{
    printf("NMAP HELP\n");
    exit(i);
}

void badOption(char *arg)
{
    printf("Bad option %s\n", arg);
    exit(1);
}

int8_t isOption(char *arg)
{
    if (strlen(arg) < 4 || arg[0] != '-' || arg[1] != '-')
        badOption(arg);
    return (TRUE);
}

void portError(char *str)
{
    printf("PORT ERROR = %s\n", str);
    exit(1);
}

void controlPort(char *input, int32_t port)
{
    if (port < 1 || port > 65535) {
        printf("port = %d\n", port);
        errorMsgExit("--port [Wrong port number]", input);
    }
}

uint32_t addPort(t_env *env, char *input, int32_t port, uint8_t type)
{
    controlPort(input, port);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] == (uint16_t)port)
            return (type);
    }
    if (env->port.nb >= 1024)
        errorMsgExit("--port [Number of ports requested exceed 1024]", input);
    env->port.list[env->port.nb] = (uint16_t)port;
    env->port.nb++;
    return (type);
}

uint32_t addPortRange(t_env *env, char *input, int32_t fport, int32_t sport)
{
    uint8_t count;

    controlPort(input, fport);
    controlPort(input, sport);
    if (fport > sport)
        errorMsgExit("--ports [Port range is backward]", input);

    for (; fport <= sport; fport++)
        addPort(env, input, fport, WO_COMMA);

    count = 1;
    for (; sport > 9; sport /= 10)
        count++;
    
    return (count + 1);
}

void controlNextPort(char *input, char next_char)
{
    if (!(next_char))
        errorMsgExit("--ports [Wrong syntax]", input);
}

uint32_t controlAfterPortRange(char *input, char next_char)
{

    if (next_char && next_char != ',')
        errorMsgExit("--ports [Wrong syntax]", input);
    else if (next_char)
        return (1);
    return (0);
}

void parsePorts(t_env *env, char *input)
{
    printf("parsePorts input = %s\n", input);
    uint32_t    fpos, spos;

    fpos = 0;
    if (!(input))
        errorMsgExit("--ports", "No port list provided");
    while (input[fpos]) {
        spos = fpos;
        while (input[spos] && isdigit(input[spos]))
            spos++;

        if (fpos == spos)
            errorMsgExit("--ports [Wrong syntax]", input);
        else if (input[spos] && input[spos] == ',') {
            controlNextPort(input, input[spos + 1]);
            fpos = addPort(env, input, atoi(&input[fpos]), W_COMMA) + spos;
        }
        else if (input[spos] && input[spos] == '-') {
            controlNextPort(input, input[spos + 1]);
            fpos = addPortRange(env, input, atoi(&input[fpos]), atoi(&input[spos + 1])) + spos;
            fpos += controlAfterPortRange(input, input[fpos]);
        }
        else if (!(input[spos])) {
            fpos = addPort(env, input, atoi(&input[fpos]), WO_COMMA) + spos;
        }
        else
            errorMsgExit("--ports", input);
    }
}

void addTarget(t_env *env, char *input)
{
    t_target        *target;
    t_target        *tmp;
    struct hostent  *host;
    struct sockaddr_in addr;

    if (!(target = (t_target *)malloc(sizeof(t_target))))
        errorMsgExit("malloc [Target allocation]", input);
    bzero(target, sizeof(t_target));

    if (!(host = gethostbyname(input)))
        errorMsgExit("ip adress or hostname", input);
    memcpy(&target->ip, host->h_addr, sizeof(struct in_addr));
    ((struct sockaddr_in *)&target->n_ip)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&target->n_ip)->sin_addr, host->h_addr, sizeof(struct in_addr));


    inet_ntop(AF_INET, &target->ip, &target->s_ip[0], INET_ADDRSTRLEN);
    if (!(&target->s_ip[0]))
        errorMsgExit("ip adress", "conversion from network format");

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &target->ip, sizeof(struct in_addr));
    if (getnameinfo((struct sockaddr *)&addr, sizeof(addr), target->s_host, 255, NULL, 0, 0) != 0)
        errorMsgExit("hostname", "reverse dns resolution");

    printf("s_host = %s\n", target->s_host);
    if (!(env->l_target))
        env->l_target = target;
    else {
        tmp = env->l_target;
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = target;
    }
}

void parseIP(t_env *env, char *input)
{
    printf("parseIP input = %s\n", input);

    if (!(input))
        errorMsgExit("--ip", "No ip address provided");
    addTarget(env, input);
}

void parseFile(t_env *env, char *input)
{
    printf("parseFile value = %s\n", input);
    FILE *file;
    char *line;
    size_t len;
    ssize_t ret;

    if (!(input))
        errorMsgExit("--file", "No file provided");
    if (!(file = fopen(input, "r")))
        errorMsgExit("--file [Cannot open file]", input);

    line = NULL;
    while ((ret = getline(&line, &len, file)) != -1) {
        line[ret - 1] = '\0';
        addTarget(env, line);
    }
    fclose(file);
    if (line)
        free(line);
}

void parseThreads(t_env *env, char *input)
{
    printf("parseThreads thread_nb = %s\n", input);
    int32_t thread_nb;

    if (!(input))
        errorMsgExit("--speedup", "No thread number provided");
    thread_nb = atoi(input);
    if (thread_nb < 0 || thread_nb > 250)
        errorMsgExit("--speedup [Wrong number of threads]", input);
    env->thread.nb = (uint8_t)thread_nb;
}

void addScanType(t_env *env, char *input, uint8_t type)
{
    if (env->scan.all & type)
        errorMsgExit("--scan [Scan type repetition]", input);
    env->scan.all |= type;
}

uint32_t controlAfterScanType(char *input, char current_char, char next_char)
{
    if (current_char && current_char != '/')
        errorMsgExit("--scan [Wrong syntax]", input);
    else if (current_char && current_char == '/' && !(next_char))
        errorMsgExit("--scan [Wrong syntax]", input);
    else if (current_char)
        return (1);
    return (0);
}

void parseScan(t_env *env, char *input)
{
    printf("parseScan value = %s\n", input);
    uint32_t    fpos, spos, tpos;
    char        type[5];

    if (!(input))
        errorMsgExit("--scan", "No scan type provided");
    fpos = 0;
    while (input[fpos]) {
        spos = fpos;
        tpos = 0;
        while (input[spos] && input[spos] != '/')
            type[tpos++] = input[spos++];
        type[tpos] = '\0';
        printf("type = %s\n", type);
        if (!(strncmp(type, "SYN", 4)))
            addScanType(env, input, SSYN);
        else if (!(strncmp(type, "ACK", 4)))
            addScanType(env, input, SACK);
        else if (!(strncmp(type, "NULL", 5)))
            addScanType(env, input, SNULL);
        else if (!(strncmp(type, "FIN", 4)))
            addScanType(env, input, SFIN);
        else if (!(strncmp(type, "XMAS", 5)))
            addScanType(env, input, SXMAS);
        else if (!(strncmp(type, "UDP", 4)))
            addScanType(env, input, SUDP);
        else
            errorMsgExit("--scan [Wrong scan type]", input);
        fpos = controlAfterScanType(input, input[spos], input[spos + 1]) + spos;
    }
    // for (int count = 7; count >= 0; count--)
    //     printf("%d", ((env->scan.all >> count) & 1));
    // printf("\n");
    
}

int8_t parseOption(t_env *env, char *arg, char *next_arg)
{
    if (!(strncmp(arg, "help", 5)))
        displayHelp(0);
    else if (!(strncmp(arg, "ports", 6)))
        parsePorts(env, next_arg);
    else if (!(strncmp(arg, "ip", 3)))
        parseIP(env, next_arg);
    else if (!(strncmp(arg, "file", 5)))
        parseFile(env, next_arg);
    else if (!(strncmp(arg, "speedup", 8)))
        parseThreads(env, next_arg);
    else if (!(strncmp(arg, "scan", 5)))
        parseScan(env, next_arg);

    return (1);
}

void parseArgs(t_env *env, int argc, char **argv)
{
    int16_t	pos;

    pos = 1;
    if (argc < 2)
        displayHelp(1);
    while (pos < argc)
    {
        if (isOption(argv[pos]))
            pos += parseOption(env, &(argv[pos][2]), argv[pos + 1]);
        pos++;
    }

    if (!(env->l_target))
        errorMsgExit("ip address or hostname", "no target provided");
    if (env->port.nb == 0)
        addPortRange(env, "default", 1, 1024);

    if (env->scan.all == 0)
        parseScan(env, "SYN/ACK/NULL/FIN/XMAS/UDP");

    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        env->port.result[pos].syn = FILT;
        env->port.result[pos].ack = FILT;
        env->port.result[pos].null = OPEN_FILT;
        env->port.result[pos].fin = OPEN_FILT;
        env->port.result[pos].xmas = OPEN_FILT;
        env->port.result[pos].udp = OPEN_FILT;
    }

    if (isThreadAvailable(env))
        env->thread.on = TRUE;


    // printf("=============\n");
    // for (uint16_t pos = 0; pos < env->port.nb; pos++) {
    //     printf("%d\n", env->port.list[pos]);
    // }
    // printf("=============\n");

    t_target *tmp;
    char ip[INET_ADDRSTRLEN];
    tmp = env->l_target;
    while (tmp) {
        bzero(&ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &tmp->ip, &ip[0], INET_ADDRSTRLEN);
        printf("ip = %s\n", ip);
        tmp = tmp->next;
    }

    printf("=============\n");

    for (int count = 7; count >= 0; count--)
        printf("%d", ((env->scan.all >> count) & 1));
    printf("\n");
    printf("=============\n");
}