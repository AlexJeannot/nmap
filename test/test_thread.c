# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <strings.h>
# include <ctype.h>
# include <poll.h>
# include <pthread.h>

void *test(void *lala)
{
    pthread_exit((void *)0);
}

int main()
{
    pthread_t id;

    pthread_create(&id, NULL, test, (void*)0);
    sleep(3);
    pthread_join(id, NULL);
}