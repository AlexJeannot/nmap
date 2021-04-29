#include "../incs/nmap.h"

/*
**  Main program
**  Init variables
**  Parse arguments
**  Get source IP
**  Create sockets
**  Display introduction
**  If threads requested
**  -- Execute program with threads
**  Else
**  -- Execute program without threads
**  Display conclusion
**  Clear resources allocated
*/
int main(int argc, char **argv)
{
    t_env       env;

    initProgram(&env);
    parseArgs(&env, argc, argv);
    getSourceIP(&env);
    createSocket(&env);

    displayIntroduction(&env);
    if (env.thread.on)
        execWithThreads(&env);
    else
        execWithoutThreads(&env);
    displayConclusion(&env);
    clearResources(&env, NULL);

    return (0);
}