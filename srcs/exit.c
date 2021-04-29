#include "../incs/nmap.h"

/*
**	Exit if error in program
*/
void	errorExit(t_env *env, char *error)
{
	fprintf(stderr, "ft_nmap: %s\n", error);
	clearResources(env, error);
	exit(1);
}

/*
**	Allocate space for error message
**	Create error message
**	Pass it to error_exit function
*/
void	errorMsgExit(t_env *env, char *option, char *arg)
{
    char *error_msg;

	if (!(error_msg = (char *)malloc(sizeof(char) * (strlen(option) + strlen(arg) + 13))))
		errorExit(env, "ft_nmap: invalid malloc [Error message allocation]");
	sprintf(error_msg, "invalid %s: '%s'", option, arg);
	errorExit(env, error_msg);
}

/*
**	Clear resources allocated in program
**	Memory and sockets
*/
void clearResources(t_env *env, char *error)
{
	t_list_target	*tmp;

	if (error)
		free(error);
	if (env->main_env->stats.host_down)
		free(env->main_env->stats.host_down);
	if (env->main_env->thread.nb)
		free(env->main_env->thread.nb);
	while (env->main_env->target.start) {
		tmp = env->main_env->target.start;
		env->main_env->target.start = env->main_env->target.start->next;
		free(tmp);
	}
	close(env->sock.icmp);
	close(env->sock.tcp);
	close(env->sock.udp);
}