#include "../incs/nmap.h"

/*
**  Set the scan result if no response from target
**  For each port provided
*/
void    setDefaultPortState(t_env *env)
{
    for (uint16_t pos = 0; pos < env->port.nb; pos++) {
        env->port.result[pos].syn = FILT;
        env->port.result[pos].ack = FILT;
        env->port.result[pos].null = OPEN_FILT;
        env->port.result[pos].fin = OPEN_FILT;
        env->port.result[pos].xmas = OPEN_FILT;
        env->port.result[pos].udp = OPEN_FILT;
    }
}

/*
**  Init variables as first step of the program
**  Save pointer to env structure because may need it for freeing resources if error exit in a thread
**  Save pointer to sig_env structure (global) because may need it for freeing resources if exit due to a signal
**  Verify user rights
**  Number of host down must be on the heap because could be shared between threads
**  Init mutex to access thread information (number/incrementation/decrementation)
**  Init mutex to display ping result
**  Init mutex to orchestrate thread communication and timing
*/
void    initProgram(t_env *env)
{
    bzero(env, sizeof(t_env));
    env->main_env = env;
    sig_env = env;
    isUserRoot(env);
    env->stats.g_start = getTsMs();
    
    if (!(env->stats.host_down = (uint64_t *)malloc(sizeof(uint64_t))))
        errorMsgExit(env, "malloc [Stats allocation]", "host down");
    bzero(env->stats.host_down, sizeof(uint64_t));

    pthread_mutex_init(&env->thread.lock, NULL);
    pthread_mutex_init(&env->display_lock, NULL);
    pthread_mutex_init(&env->sniffer.lock, NULL);
    setSignalHandler(env);
}

/*
**  Verify and set default parameters after parsing arguments
**  Exit if no target provided (only mandatory argument)
**  If no port range provided then 1-1024
**  If no scan type provided then all
*/
void    setDefautParams(t_env *env)
{
    if (!(env->target.list))
        errorMsgExit(env, "ip address or hostname", "no target provided");
    env->target.start = env->target.list;

    if (env->port.nb == 0)
        addPortRange(env, "default", 1, 1024);

    if (env->scan.all == 0)
        parseScan(env, "SYN/ACK/NULL/FIN/XMAS/UDP");

    if (env->thread.nb && isThreadAvailable(env))
        env->thread.on = TRUE;
}

/*
**  Sort port by number
**  Must sort result accordingly
*/
void    sortPort(t_env *env)
{
    uint16_t    tmp_port, s_pos;
    t_result    tmp_res;

    s_pos = 0;
    for (uint16_t a_pos = 0; a_pos < env->port.nb; a_pos++) {
        for (uint16_t f_pos = 0; f_pos < (env->port.nb - 1); f_pos++) {
            s_pos = f_pos + 1;
            if (env->port.list[f_pos] > env->port.list[s_pos]) {
                tmp_port = env->port.list[f_pos];
                env->port.list[f_pos] = env->port.list[s_pos];
                env->port.list[s_pos] = tmp_port;

                tmp_res = env->port.result[f_pos];
                env->port.result[f_pos] = env->port.result[s_pos];
                env->port.result[s_pos] = tmp_res;
            }
        }
    }
}

void	*ft_memset(void *s, int c, size_t n)
{
	unsigned char	*str;

	str = (unsigned char *)s;
	while (n > 0)
	{
		*str = (unsigned char)c;
		str++;
		n--;
	}
	return (s);
}

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char	*destcpy;
	unsigned char	*srccpy;
	unsigned int	cmp;

	cmp = 0;
	destcpy = (unsigned char *)dest;
	srccpy = (unsigned char *)src;
	if (!n || destcpy == srccpy)
		return (dest);
	while (n > cmp)
	{
		destcpy[cmp] = srccpy[cmp];
		cmp++;
	}
	return (dest);
}

size_t		ft_strlen(const char *s)
{
	unsigned int	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

size_t	ft_strlcpy(char *dest, const char *src, size_t size)
{
	unsigned int	i;
	unsigned int	j;

	if (!dest)
		return (0);
	i = 0;
	j = ft_strlen(src);
	if (!size)
		return (j);
	while (src[i] && i < size - 1)
	{
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
	return (j);
}