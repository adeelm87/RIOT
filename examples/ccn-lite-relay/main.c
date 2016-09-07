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

#include "xtimer.h"
#include "abe_relic.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* 10kB buffer for the heap should be enough for everyone */
#define TLSF_BUFFER     (10240 / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

/*!
 * Encrypts data and appends the time it took to encrypt.
 * Beware: in must at least have an allocated size of (in_len + 4), otherwise
 * it will crash when appending time.
 *
 * @param[out] out				The encrypted data
 * @param[out] out_len			The length of the encrypted data
 * @param[in]  in				The data to encrypt
 * @param[in]  in_len			The length of the data to encrypt
 * @param[in]  pol				The policy to encrypt under
 * @param[in]  public_params	The public parameters of the system
 * @return						An error code, 0 if successful
 */
int cp_encrypt_append_time(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, char *pol, fenc_public_params_WatersCP public_params){

	xtimer_t xtimer;
	uint32_t start, end, elapsed_ms;
	int err = 0;
	uint8_t enc_key[16], IV[16] = {0};
	ciphertext_WatersCP ct;

	start = xtimer_now();
	err = cp_encrypt(enc_key, &ct, pol, public_params);
	end = xtimer_now();
	if (err != 0)
		return err;

	elapsed_ms = (end - start)/1000;
	in_len += uint_to_bytes(in + in_len, elapsed_ms);

	err = bc_aes_cbc_enc(out, out_len, in, in_len, enc_key, 128, IV);
	return err;
}

int cp_check_time(void){
	init_abe_relic();
	fenc_scheme_context_WatersCP context;
	ciphertext_WatersCP ct;
	fenc_key_WatersCP key;
	uint8_t dec[16], out[48], IV[16] = {0}, in_msg[30];
	char *pol = "A1ONE and A1TWO", encThis[25] = "SeeEcRet",
			*attrs = "A1ONE,A1TWO", dec_msg[100], final[100];
	int out_len = 48, dec_msg_len = 100, in_msg_len = 30, msg_len, enc_time;

	int_to_bytes(in_msg, strlen(encThis));
	memcpy(in_msg + 4, encThis, strlen(encThis));

	cp_setup(&context);
	cp_encrypt_append_time(out, &out_len, in_msg, strlen(encThis) + 4, pol,
			context.public_params);

//	cp_keygen(&key, &context, attrs);
//	cp_decrypt(dec, &key, ct);
//
//	bc_aes_cbc_dec((uint8_t*)dec_msg, &dec_msg_len, out, out_len, dec, 128, IV);
//	bytes_to_int(&msg_len, (uint8_t*)dec_msg);
//	memcpy(final, dec_msg + 4, msg_len);
//	bytes_to_int(&enc_time, (uint8_t*)dec_msg + 4 +msg_len);
//
//
//	printf("%s/n", final);
//	printf("Time for enc %d/n", enc_time);
	return 0;

}

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");
    cp_check_time();
    ccnl_core_init();

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
