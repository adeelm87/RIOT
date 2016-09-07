/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       An example of how abe_relic is used in a project.
 *
 * @}
 */


#include <abe_relic.h>
#include "abe_thread.h"
#include "xtimer.h"
#include "shell.h"
#include "thread.h"
#include "msg.h"


char abe_stack[80*1024];

int main(void)
{
	printf("Hello World!\n");

	kernel_pid_t abe_pid = thread_create(abe_stack, sizeof(abe_stack),
			THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST,
            abe_thread, NULL, "abe");


    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
