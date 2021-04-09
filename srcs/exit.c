#include "../incs/nmap.h"

/*
 * Exit if error in program
*/
void	error_exit(char *error)
{
	fprintf(stderr, "ft_nmap: %s\n", error);
	exit(1);
}

/*
 * Allocate space for error message
 * Create error message
 * Pass it to error_exit function
*/
void	errorMsgExit(char *option, char *arg)
{
    char *error_msg;

	if (!(error_msg = (char *)malloc(sizeof(char) * (strlen(option) + strlen(arg) + 13))))
		error_exit("Error message memory allocation failed");
	sprintf(error_msg, "invalid %s: '%s'", option, arg);
	error_exit(error_msg);
}