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
#include "xtimer.h"

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

int main(void)
{
	xtimer_t timerx;
	uint32_t a,b;
	printf("Hello World! \n");
	b = xtimer_now(); // returns current system time in 32 bit microsecond value
//	ma_abe_example();
	cp_abe_example();
	a = xtimer_now();
	uint32_t ans = (a-b)/1000;
	printf("Time for ma_abe_example(): %u\n", ans);
	printf("Success!!\n");
    return 0;
}
