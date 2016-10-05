/*
 * Copyright (C) 2015 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Basic ccn-lite relay example (produce and consumer via shell)
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "ccn-lite-riot.h"
#include "thread.h"
#include "abe_relic.h"
#include "button_listen.h"
#include "board.h"

/* sc_ccnl.c forward declaration */
int _ccnl_open(int argc, char **argv);

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#define TLSF_BUFFER     ((1024*15) / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

char abe_stack[1024*45];
char button_stack[1024*5];

int main(void)
{
	//LED3_ON;
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

    /*ccnl_core_init();
    char *cmd[2] = {"ccnl_open", "3"};
    _ccnl_open(2, cmd);*/

	/*kernel_pid_t abe_pid = thread_create(abe_stack, sizeof(abe_stack),
			THREAD_PRIORITY_MAIN, THREAD_CREATE_STACKTEST,
            abe_thread, NULL, "abe");*/

	/*kernel_pid_t button = thread_create(button_stack,sizeof(button_stack),
			THREAD_PRIORITY_MAIN , THREAD_CREATE_STACKTEST,
			button_listen_thread, NULL, "button_listen");*/

//    char line_buf[SHELL_DEFAULT_BUFSIZE];
//    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
