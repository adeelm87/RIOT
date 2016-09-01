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


/*!
 * Encrypts data with CP-ABE and appends the time it took to encrypt.
 * Beware: in must at least have an allocated size of (in_len + 4), otherwise
 * it will crash when appending time.
 *
 * @param[out] out				The encrypted data + serialized ct appended
 * @param[out] out_len			The length of the output buffer
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
	int err = 0, ct_s_len;
	uint8_t enc_key[16], IV[16] = {0};
	ciphertext_WatersCP ct;

	start = xtimer_now();
	err = cp_encrypt(enc_key, &ct, pol, public_params);
	end = xtimer_now();
	if (err != 0)
		return err;

	elapsed_ms = (end - start)/1000;
	in_len += uint_to_bytes(in + in_len, elapsed_ms);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, enc_key, 128, IV);
	int_to_bytes(out, *out_len);
	ct_s_len = CT_to_bytes(out + *out_len + 8, ct);
	*out_len += int_to_bytes(out + *out_len + 4, ct_s_len);
	*out_len += ct_s_len;

	return err;
}

/*!
 * Encrypts data with CP-ABE and appends the time it took to encrypt.
 * Beware: in must at least have an allocated size of (in_len + 4), otherwise
 * it will crash when appending time.
 *
 * @param[out] out				The encrypted data + serialized ct appended
 * @param[out] out_len			The length of the output buffer
 * @param[in]  in				The data to encrypt
 * @param[in]  in_len			The length of the data to encrypt
 * @param[in]  pol				The policy to encrypt under
 * @param[in]  public_params	The public parameters of the system
 * @return						An error code, 0 if successful
 */
int cp_encrypt_append_metadata_str(uint8_t *out, int *out_len, uint8_t *in,
		int in_len, char *pol, fenc_public_params_WatersCP public_params){

	char tmp_str[30];
	xtimer_t xtimer;
	uint32_t start, end, elapsed_ms;
	int err = 0, ct_s_len;
	uint8_t enc_key[16], IV[16] = {0}, ct_buff[4096];
	ciphertext_WatersCP ct;

	start = xtimer_now();
	err = cp_encrypt(enc_key, &ct, pol, public_params);
	end = xtimer_now();
	if (err != 0)
		return err;

	ct_s_len = CT_to_bytes(ct_buff, ct);
	elapsed_ms = (end - start)/1000;
	sprintf(tmp_str, ",%d,%d", (int)elapsed_ms, ct_s_len);
	memcpy(in + in_len, tmp_str, strlen(tmp_str));
	in_len += strlen(tmp_str);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, enc_key, 128, IV);
	int_to_bytes(out, *out_len);
	*out_len += int_to_bytes(out + *out_len + 4, ct_s_len);
	memcpy(out + *out_len + 4, ct_buff, ct_s_len);
	*out_len += ct_s_len + 4;

	return err;
}
/*!
 * Encrypts data with MA-ABE and appends the time it took to encrypt.
 * Beware: in must at least have an allocated size of (in_len + 4), otherwise
 * it will crash when appending time.
 *
 * @param[out] out				The encrypted data + serialized ct appended
 * @param[out] out_len			The length of the output buffer
 * @param[in]  in				The data to encrypt
 * @param[in]  in_len			The length of the data to encrypt
 * @param[in]  pol				The policy to encrypt under
 * @param[in]  gp				The global parameters of the system
 * @param[in]  pks				An array of pks (or address of one)
 * @param[in]  nr_pks			The size of the array pks
 * @return						An error code, 0 if successful
 */
int ma_encrypt_append_time(uint8_t *out, int *out_len, uint8_t *in, int in_len,
		char *pol, ma_global_params gp, auth_public_key *pks, int nr_pks){
	xtimer_t xtimer;
	uint32_t start, end, elapsed_ms;
	int err = 0, ct_s_len;
	uint8_t enc_key[16], IV[16] = {0};
	ma_ciphertext ct;
	fenc_attribute_policy p;


	start = xtimer_now();
	err = gen_policy(&p, pol);
	if (err != 0)
		return err;

	err = ma_encrypt(enc_key, &ct, gp, pks, nr_pks, p);
	end = xtimer_now();

	if (err != 0)
		return err;

	elapsed_ms = (end - start)/1000;

	in_len += uint_to_bytes(in + in_len, elapsed_ms);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, enc_key, 128, IV);
	int_to_bytes(out, *out_len);
	ct_s_len = maCT_to_bytes(out + *out_len + 8, ct);
	*out_len += int_to_bytes(out + *out_len + 4, ct_s_len);
	*out_len += ct_s_len;

	return err;

}

/*!
 * Encrypts data with MA-ABE and appends the time it took to encrypt.
 * Beware: in must at least have an allocated size of (in_len + 4), otherwise
 * it will crash when appending time.
 *
 * @param[out] out				The encrypted data + serialized ct appended
 * @param[out] out_len			The length of the output buffer
 * @param[in]  in				The data to encrypt
 * @param[in]  in_len			The length of the data to encrypt
 * @param[in]  pol				The policy to encrypt under
 * @param[in]  gp				The global parameters of the system
 * @param[in]  pks				An array of pks (or address of one)
 * @param[in]  nr_pks			The size of the array pks
 * @return						An error code, 0 if successful
 */
int ma_encrypt_append_metadata_str(uint8_t *out, int *out_len, uint8_t *in, int in_len,
		char *pol, ma_global_params gp, auth_public_key *pks, int nr_pks){
	xtimer_t xtimer;
	uint32_t start, end, elapsed_ms;
	int err = 0, ct_s_len;
	uint8_t enc_key[16], IV[16] = {0}, ct_buff[4096];
	ma_ciphertext ct;
	fenc_attribute_policy p;
	char tmp_str[128];


	start = xtimer_now();
	err = gen_policy(&p, pol);
	if (err != 0)
		return err;

	err = ma_encrypt(enc_key, &ct, gp, pks, nr_pks, p);
	end = xtimer_now();
	if (err != 0)
		return err;

	ct_s_len = maCT_to_bytes(ct_buff, ct);
	elapsed_ms = (end - start)/1000;
	sprintf(tmp_str, ",%d,%d", (int)elapsed_ms, ct_s_len);
	memcpy(in + in_len, tmp_str, strlen(tmp_str));
	in_len += strlen(tmp_str);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, enc_key, 128, IV);
	int_to_bytes(out, *out_len);
	*out_len += int_to_bytes(out + *out_len + 4, ct_s_len);
	memcpy(out + *out_len + 4, ct_buff, ct_s_len);
	*out_len += ct_s_len + 4;

	return err;

}

int ma_check_time(void){
	ma_global_params gp;
	ma_ciphertext ct;
	ma_prv_key key;
	auth_public_key pk;
	auth_secret_key sk;
	uint8_t dec[16], out[3096], IV[16] = {0}, in_msg[30];
	char *pol = "A1ONE and A2ONE and A1TWO", encThis[25] = "SeeEcRet",
				*attrs = "A1ONE,A2ONE,A1TWO", dec_msg[100], final[100], *auth_attrs[3];
	int out_len = 3096, dec_msg_len = 100, in_msg_len = 0, msg_len, enc_time,
				enc_msg_len, ct_s_len, ct_d_len, err = 0;

	auth_attrs[0] = "A1ONE";
	auth_attrs[1] = "A1TWO";
	auth_attrs[2] = "A2ONE";

	init_abe_relic();

	in_msg_len += int_to_bytes(in_msg, strlen(encThis));
	memcpy(in_msg + 4, encThis, strlen(encThis));
	in_msg_len += strlen(encThis);

	global_setup(&gp);
	err = authority_setup(&pk, &sk, gp, 3, auth_attrs);

	err = ma_encrypt_append_time(out, &out_len, in_msg, in_msg_len, pol, gp, &pk, 1);
	if (err != 0)
		return err;

	bytes_to_int(&enc_msg_len, out);
	bytes_to_int(&ct_s_len, out + enc_msg_len + 4);
	ct_d_len = bytes_to_maCT(&ct, out + enc_msg_len + 8);
	if (ct_s_len != ct_d_len ){
		err = -7;
		return err;
	}

	err = ma_keygen(&key, attrs, &sk, 1, gp);
	if (err != 0)
		return err;

	err = ma_decrypt(dec, ct, &key, gp);
	if (err != 0)
		return err;

	bc_aes_cbc_dec((uint8_t*)dec_msg, &dec_msg_len, out + 4, enc_msg_len, dec, 128, IV);
	bytes_to_int(&msg_len, (uint8_t*)dec_msg);
	final[msg_len] = '\0';
	memcpy(final, dec_msg + 4, msg_len);
	bytes_to_int(&enc_time, (uint8_t*)dec_msg + 4 +msg_len);

	printf("%s\n", final);
	printf("Time for enc %d\n", enc_time);

	return err;
}

int cp_check_time(void){
	init_abe_relic();
	fenc_scheme_context_WatersCP context;
	ciphertext_WatersCP ct;
	fenc_key_WatersCP key;
	uint8_t dec[16], out[1024], IV[16] = {0}, in_msg[30];
	char *pol = "A1ONE and A1TWO", encThis[25] = "SeeEcRet",
			*attrs = "A1ONE,A1TWO", dec_msg[100], final[100];
	int out_len = 1024, dec_msg_len = 100, in_msg_len = 0, msg_len, enc_time,
			enc_msg_len, ct_s_len, ct_d_len;

	in_msg_len += int_to_bytes(in_msg, strlen(encThis));
	memcpy(in_msg + 4, encThis, strlen(encThis));
	in_msg_len += strlen(encThis);

	cp_setup(&context);
	int err = cp_encrypt_append_time(out, &out_len, in_msg, in_msg_len , pol,
			context.public_params);
	if (err != 0)
		return err;

	bytes_to_int(&enc_msg_len, out);
	bytes_to_int(&ct_s_len, out + enc_msg_len + 4);
	ct_d_len = bytes_to_CT(&ct, out + enc_msg_len + 8);
	if (ct_s_len != ct_d_len ){
		err = -7;
		return err;
	}

	cp_keygen(&key, &context, attrs);
	cp_decrypt(dec, &key, ct);

	bc_aes_cbc_dec((uint8_t*)dec_msg, &dec_msg_len, out + 4, enc_msg_len, dec, 128, IV);
	bytes_to_int(&msg_len, (uint8_t*)dec_msg);
	final[msg_len] = '\0';
	memcpy(final, dec_msg + 4, msg_len);
	bytes_to_int(&enc_time, (uint8_t*)dec_msg + 4 +msg_len);


	printf("%s\n", final);
	printf("Time for enc %d\n", enc_time);
	return 0;

}

int cp_check_RAM(void){
	fenc_scheme_context_WatersCP context;
	uint8_t out[2048], in[2048];
	int out_len = 2048, in_len = 0, err = 0;
	char *pol = "A1ONE and A1TWO and A1THREE", *msg = "Hiho this is a message to encrypt "
			"of arbitrary length\n";

	memcpy(in + 4, msg, strlen(msg));
	in_len += int_to_bytes(in, strlen(msg));
	in_len += strlen(msg);

	init_abe_relic();
	cp_setup(&context);
	err = cp_encrypt_append_time(out, &out_len, in, in_len, pol,
			context.public_params);
	return err;
}

int ma_check_RAM(void){
	char *auth_attrs[3], *pol = "A1ONE and A2ONE and A1TWO",
			encThis[25] = "SeeEcRet";
	ma_global_params gp;
	auth_public_key pk;
	auth_secret_key sk;
	int out_len = 3096, in_msg_len = 0, err = 0;
	uint8_t out[3096],in_msg[30];

	init_abe_relic();

	auth_attrs[0] = "A1ONE";
	auth_attrs[1] = "A1TWO";
	auth_attrs[2] = "A2ONE";

	in_msg_len += int_to_bytes(in_msg, strlen(encThis));
	memcpy(in_msg + 4, encThis, strlen(encThis));
	in_msg_len += strlen(encThis);

	global_setup(&gp);
	err = authority_setup(&pk, &sk, gp, 3, auth_attrs);

	err = ma_encrypt_append_time(out, &out_len, in_msg, in_msg_len, pol, gp,
			&pk, 1);

	return err;

}

/*!
 * Encrypts the payload in ei and outputs it in out.
 *
 * [out] = [enc_msg_len (int) | enc_msg | ct_len (int) | ct ]
 * [msg] = [payload_len (int) | payload | time_for_enc (int)]
 *
 * @param[out]    out 		Byte array of encrypted data + ct
 * @param[in/out] out_len	Length of output byte array
 * @param[in]	  ei		Contains policy, MA or CP and payload
 */
//int enc_from_ei(uint8_t *out, int *out_len, enc_info *ei){
//	uint8_t in[1024];
//	int err = 0, max_out = *out_len, in_len;
//
//	in_len = int_to_bytes(in, ei->len);
//	memcpy(in + in_len, ei->payload, ei->len);
//	in_len += ei->len;
//
//	if (ei->MA){
//		ma_global_params gp;
//		auth_public_key pk;
//		ma_set_global_params(&gp);
//		ma_set_auth_pk(&pk, gp);
//
//		err = ma_encrypt_append_time(out, out_len, in, in_len, ei->pol_str,
//				gp, &pk, 1);
//	}else{
//		fenc_public_params_WatersCP public_params;
//		cp_set_public_params(&public_params);
//
//		err = cp_encrypt_append_time(out, out_len, in, in_len, ei->pol_str,
//				public_params);
//
//	}
//
//	if (*out_len > max_out)
//			printf("Error: The out buffer overflowed.\n");
//
//	return err;
//}

/*!
 * Put the data on the format "type,data,time,ciphertext_size" and then prepends
 * the length of this string in serialized format and then encrypts this.
 *
 * e.g. payload = [ser_len |"t,24,2342,1923"]
 *
 */
int format_enc(uint8_t *out, int *out_len, char type, int data, int MA,
		char *pol_str){
	int max_out = *out_len, in_len, err;
	uint8_t in[256];
	char str[128];

	sprintf(str, "%c,%d", type, data);
	memcpy(in, str, strlen(str));
	in_len = strlen(str);

	if (MA){
		ma_global_params gp;
		auth_public_key pk;
		ma_set_global_params(&gp);
		ma_set_auth_pk(&pk, gp);

		err = ma_encrypt_append_metadata_str(out, out_len, in, in_len, pol_str,
				gp, &pk, 1);
	}else{
		fenc_public_params_WatersCP public_params;
		cp_set_public_params(&public_params);

		err = cp_encrypt_append_metadata_str(out, out_len, in, in_len, pol_str,
				public_params);

	}

	if (*out_len > max_out)
		printf("Error: The out buffer overflowed.\n");

	return err;
}

int format_decryption_check(uint8_t *data_ct, int MA){
	init_abe_relic();
	int enc_msg_len, ct_s_len, err = 0, out_len = 4096;
	uint8_t dec[16], IV[BC_LEN] = {0}, out[4096];
	char str[128];


	bytes_to_int(&enc_msg_len, data_ct);
	bytes_to_int(&ct_s_len, data_ct + 4 + enc_msg_len);

	if (MA)
		err = ma_fix_dec(dec, data_ct + 8 + enc_msg_len, ct_s_len);
	else
		err = cp_fix_dec(dec, data_ct + 8 + enc_msg_len, ct_s_len);

	if (err != 0){
		return err;
	}

	err = bc_aes_cbc_dec(out, &out_len, data_ct + 4, enc_msg_len, dec, 128, IV);
	if (err != 0){
		printf("error at block cipher\n");
	}

	memcpy(str, out, out_len);

	printf("On format:'type,data,enc_time,ct_size'\n");
	printf("Dec string: %s\n", str);

	clean_abe_relic();
	return err;
}



void* abe_thread(void *arg){
	init_abe_relic();

	uint8_t out[4096];
	int out_len = 4096;
	int *a;
	msg_t m;


	while (1){
		msg_receive(&m);
		a = m.content.ptr;
		printf("in abe thread: %p\n", a);
		format_enc(out, &out_len, 't', 123, 1, "A1ONE and A1TWO");
		printf("Outlen: %d\n", out_len);
		format_decryption_check(out, 1);
		m.content.ptr = out;
		msg_reply(&m, &m);
		msg_receive(&m);
	}

	clean_abe_relic();

	return NULL;
}

int ma_fix_dec(uint8_t *dec, uint8_t *ct_buff, int ct_s_len){
	ma_global_params gp;
	ma_ciphertext ct;
	ma_prv_key key;
	auth_secret_key sk;
	char *attrs = "A1ONE,A1TWO,A2ONE,A3ONE";
	int ct_d_len, err = 0;

	ma_set_global_params(&gp);
	ma_set_auth_sk(&sk);
	ma_keygen(&key, attrs, &sk, 1, gp);
	ct_d_len = bytes_to_maCT(&ct, ct_buff);
	if (ct_d_len != ct_s_len){
		err = -7;
		return err;
	}
	err = ma_decrypt(dec, ct, &key, gp);

	return err;
}

int cp_fix_dec(uint8_t *dec, uint8_t *ct_buff, int ct_s_len){
	ciphertext_WatersCP ct;
	fenc_key_WatersCP key;
	fenc_scheme_context_WatersCP context;
	char *attrs = "A1ONE,A1TWO";
	int ct_d_len, err  = 0;

	cp_set_public_params(&(context.public_params));
	cp_set_secret_params(&(context.secret_params));
	cp_keygen(&key, &context, attrs);
	ct_d_len = bytes_to_CT(&ct, ct_buff);
	if (ct_s_len != ct_d_len){
		err = -7;
		return err;
	}

	err = cp_decrypt(dec, &key, ct);
	return err;
}

/*!
 * Decrypts a message encrypted with "enc_from_ei".
 */
int decryption_check(uint8_t *data_ct, int MA){
	init_abe_relic();
	int enc_msg_len, ct_s_len, err = 0, out_len = 4096, msg_len,
			elapsed_ms, temp;
	uint8_t dec[16], IV[BC_LEN] = {0}, out[4096];


	bytes_to_int(&enc_msg_len, data_ct);
	bytes_to_int(&ct_s_len, data_ct + 4 + enc_msg_len);

	if (MA)
		err = ma_fix_dec(dec, data_ct + 8 + enc_msg_len, ct_s_len);
	else
		err = cp_fix_dec(dec, data_ct + 8 + enc_msg_len, ct_s_len);

	if (err != 0){
		return err;
	}

	print_byte_array(data_ct + 4, enc_msg_len);
	err = bc_aes_cbc_dec(out, &out_len, data_ct + 4, enc_msg_len, dec, 128, IV);
	print_byte_array(out, out_len);
	if (err != 0){
		printf("error at block cipher\n");
	}
	bytes_to_int(&msg_len, out);
	bytes_to_int(&temp, out + msg_len);
	bytes_to_int(&elapsed_ms, out + 4 + msg_len);

	printf("Temperature %d\n", temp);
	printf("Elapsed ms: %d\n", elapsed_ms);

	clean_abe_relic();
	return err;
}

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
