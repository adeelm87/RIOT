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

/*
 * sc_ccnl.c forward declarations
 */
int _ccnl_open(int argc, char **argv);
int _ccnl_fib(int argc, char **argv);

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     ((5*10240) / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");

    printf("Testing printf!!\n");

    ccnl_core_init();

    /*
     * Untidy code block, fix later.
     */
    char ccn_open_cmd[] = "ccnl_open";
    char ccn_fib_cmd[] = "ccnl_fib";
    char enddev1_addr[] = "33:35:51:05:37:0b:39:22";
    char enddev2_addr[] = "33:35:51:04:37:02:39:7e";
    char* cmd[4];
    cmd[0] = ccn_open_cmd; cmd[1] = "3";
    _ccnl_open(2, cmd);
    cmd[0] = ccn_open_cmd; cmd[1] = "4";
    _ccnl_open(2, cmd);
    cmd[0] = ccn_fib_cmd; cmd[1] = "add"; cmd[2] = "/temperature"; cmd[3] = enddev1_addr;
    _ccnl_fib(4, cmd);
    cmd[2] = "/heartrate"; cmd[3] = enddev2_addr;
    _ccnl_fib(4, cmd);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
