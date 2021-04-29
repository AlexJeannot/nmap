#include "../incs/nmap.h"


/* ----------------- PORTS ----------------- */

/*
**  Control if port is in 1-65535 range
*/
void        controlPort(t_env *env, char *input, int32_t port)
{
    if (port < 1 || port > 65535) {
        errorMsgExit(env, "--port [Wrong port number]", input);
    }
}

/*
**  Add port to port array
**  Control port
**  If port already in array then stop here
**  If port range superior to 1024 then exit here
**  Add port to array
**  Increment port number
*/
uint32_t    addPort(t_env *env, char *input, int32_t port, uint8_t type)
{
    controlPort(env, input, port);
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        if (env->port.list[pos] == (uint16_t)port)
            return (type);
    }
    if (env->port.nb >= 1024)
        errorMsgExit(env, "--port [Number of ports requested exceed 1024]", input);
    env->port.list[env->port.nb] = (uint16_t)port;
    env->port.nb++;
    return (type);
}

/*
**  Add port range to port array
**  Control first port and second port
**  If second port is less than first port the exit here
**  For each port in range
**  -- Add port to array
*/
uint32_t    addPortRange(t_env *env, char *input, int32_t fport, int32_t sport)
{
    uint8_t count;

    controlPort(env, input, fport);
    controlPort(env, input, sport);
    if (fport > sport)
        errorMsgExit(env, "--ports [Port range is backward]", input);

    for (; fport <= sport; fport++)
        addPort(env, input, fport, WO_COMMA);

    count = 1;
    for (; sport > 9; sport /= 10)
        count++;
    
    return (count + 1);
}

/*
**  Control if port after separator (comma or middle dash)
*/
void        controlNextPort(t_env *env, char *input, char next_char)
{
    if (!(next_char))
        errorMsgExit(env, "--ports [Wrong syntax]", input);
}

/*
**  Control if comma after middle dash
*/
uint32_t    controlAfterPortRange(t_env *env, char *input, char next_char)
{

    if (next_char && next_char != ',')
        errorMsgExit(env, "--ports [Wrong syntax]", input);
    else if (next_char)
        return (1);
    return (0);
}

/*
**  Parse port option
**  If no input then exit here
**  While there is char in argument
**  -- Go through all digit
**  -- If no digit then exit here
**  -- If comma then add port
**  -- If middle dash then add port range
**  -- If NULL then add port and is end
**  -- Else character not accepted and then exit here
*/
void        parsePorts(t_env *env, char *input)
{
    uint32_t    fpos, spos;

    fpos = 0;
    if (!(input))
        errorMsgExit(env, "--ports", "No port list provided");
    while (input[fpos]) {
        spos = fpos;
        while (input[spos] && isdigit(input[spos]))
            spos++;

        if (fpos == spos)
            errorMsgExit(env, "--ports [Wrong syntax]", input);
        else if (input[spos] && input[spos] == ',') {
            controlNextPort(env, input, input[spos + 1]);
            fpos = addPort(env, input, atoi(&input[fpos]), W_COMMA) + spos;
        }
        else if (input[spos] && input[spos] == '-') {
            controlNextPort(env, input, input[spos + 1]);
            fpos = addPortRange(env, input, atoi(&input[fpos]), atoi(&input[spos + 1])) + spos;
            fpos += controlAfterPortRange(env, input, input[fpos]);
        }
        else if (!(input[spos])) {
            fpos = addPort(env, input, atoi(&input[fpos]), WO_COMMA) + spos;
        }
        else
            errorMsgExit(env, "--ports", input);
    }
}


/* ----------------- IP & FILE ----------------- */

/*
**  Add target to target linked list
**  Get host by name from input
**  -- If it failed then invalid IP address or hostname and then exit here
**  If input already provided then stop here
**  Retrieve information about target and copy it in target structure
**  Convert in_addr in string for future use
**  Do reverse DNS resolution
**  Add target to target linked list
*/
void        addTarget(t_env *env, char *input)
{
    t_list_target       *target, *tmp;
    struct hostent      *host;
    struct sockaddr_in  addr;

    if (!(host = gethostbyname(input)))
        errorMsgExit(env, "ip adress or hostname", input);
    if (isHostDuplicate(env, host))
        return ;

    if (!(target = (t_list_target *)malloc(sizeof(t_list_target))))
        errorMsgExit(env, "malloc [Target allocation]", input);
    bzero(target, sizeof(t_list_target));

    memcpy(&target->ip, host->h_addr, sizeof(struct in_addr));
    ((struct sockaddr_in *)&target->n_ip)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in *)&target->n_ip)->sin_addr, host->h_addr, sizeof(struct in_addr));

    inet_ntop(AF_INET, &target->ip, &target->s_ip[0], INET_ADDRSTRLEN);
    if (!(&target->s_ip[0]))
        errorMsgExit(env, "ip adress", "conversion from network format");

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &target->ip, sizeof(struct in_addr));
    if (getnameinfo((struct sockaddr *)&addr, sizeof(addr), target->s_host, 255, NULL, 0, 0) != 0)
        errorMsgExit(env, "hostname", "reverse dns resolution");

    env->target.nb++;
    if (!(env->target.list))
        env->target.list = target;
    else {
        tmp = env->target.list;
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = target;
    }
}

/*
**  Parse argument from --ip option
*/
void        parseIP(t_env *env, char *input)
{
    if (!(input))
        errorMsgExit(env, "--ip", "No ip address provided");
    addTarget(env, input);
}

/*
**  Parse argument from --file option
**  Open file
**  Get each line and add it as target
**  Close file
**  Free returned pointer
*/
void        parseFile(t_env *env, char *input)
{
    FILE    *file;
    char    *line;
    size_t  len;
    ssize_t ret;

    if (!(input))
        errorMsgExit(env, "--file", "No file provided");
    if (!(file = fopen(input, "r")))
        errorMsgExit(env, "--file [Cannot open file]", input);

    line = NULL;
    while ((ret = getline(&line, &len, file)) != -1) {
        line[ret - 1] = '\0';
        addTarget(env, line);
    }
    fclose(file);
    if (line)
        free(line);
}


/* ----------------- THREADS ----------------- */

/*
**  Parse argument from --speedup option
**  Must be between 0 and 250
*/
void        parseThreads(t_env *env, char *input)
{
    int32_t thread_nb;

    if (!(env->thread.nb = (uint8_t *)malloc(sizeof(uint8_t))))
        errorMsgExit(env, "malloc [Thread number allocation]", input);
    if (!(input))
        errorMsgExit(env, "--speedup", "No thread number provided");
    for (uint64_t pos = 0; pos < strlen(input); pos++)
        if (!(isdigit(input[pos])))
            errorMsgExit(env, "--speedup [wrong value]", input);
    thread_nb = atoi(input);
    if (thread_nb < 0 || thread_nb > 250)
        errorMsgExit(env, "--speedup [Wrong number of threads]", input);
    *(env->thread.nb) = (uint8_t)thread_nb;
}


/* ----------------- SCAN TYPES ----------------- */

/*
**  Add scan type to uint8_t (for value of each scan type see header file incs/nmap.h)
*/
void        addScanType(t_env *env, char *input, uint8_t type)
{
    if (env->scan.all & type)
        errorMsgExit(env, "--scan [Scan type repetition]", input);
    env->scan.all |= type;
}

/*
**  Verify next scan type (if there is one)
**  After a scan type next character must be nothing (end) or and '/'
**  After a '/' there must be a character as well
*/
uint8_t     controlAfterScanType(t_env *env, char *input, char current_char, char next_char)
{
    if (current_char && current_char != '/')
        errorMsgExit(env, "--scan [Wrong syntax]", input);
    else if (current_char && current_char == '/' && !(next_char))
        errorMsgExit(env, "--scan [Wrong syntax]", input);
    else if (current_char)
        return (TRUE);
    return (FALSE);
}

/*
**  Parse argument from --scan option
**  Verify and add each scan type requested
*/
void        parseScan(t_env *env, char *input)
{
    uint32_t    fpos, spos, tpos;
    char        type[5];

    if (!(input))
        errorMsgExit(env, "--scan", "No scan type provided");
    fpos = 0;
    while (input[fpos]) {
        spos = fpos;
        tpos = 0;
        while (input[spos] && input[spos] != '/')
            type[tpos++] = input[spos++];
        type[tpos] = '\0';
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
            errorMsgExit(env, "--scan [Wrong scan type]", input);
        fpos = controlAfterScanType(env, input, input[spos], input[spos + 1]) + spos;
    }
}

/* ----------------- GLOBAL ----------------- */

/*
**  Parse option requested and call a handling function accordingly
**  Return FALSE if unknown argument
*/
int8_t      parseOption(t_env *env, char *arg, char *next_arg)
{
    if (!(strncmp(arg, "help", 5)))
        displayHelp(env, 0);
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
    else
        return (FALSE);

    return (TRUE);
}

/*
**  Parse all arguments provided by user
**  For each argument
**  -- Verify if it has the option format (--option)
**  -- Verify if it is an known option
**  Set defaut parameter for not provided argument(s)
*/
void        parseArgs(t_env *env, int argc, char **argv)
{
    int16_t pos;

    pos = 1;
    if (argc < 2)
        displayHelp(env, 1);
    while (pos < argc)
    {
        if (isOption(env, argv[pos])) {
            if (!(parseOption(env, &(argv[pos][2]), argv[pos + 1]))) {
                printf("ft_nmap: invalid argument: %s\n", argv[pos]);
                displayHelp(env, 1);
            }
        }
        pos += 2;
    }
    setDefautParams(env);
    setDefaultPortState(env);
}