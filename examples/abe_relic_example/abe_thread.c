/*
 * abe_thread.c
 *
 *  Created on: Aug 31, 2016
 *      Author: joakim
 */
#include "abe_relic.h"
#include "abe_thread.h"
#include "xtimer.h"

enc_metadata *__enc_info;

/*!
 * Formats the input to a payload on the format: "type,data,enc_time,ct_size"
 * and uses the most recently generated symmetric key to encrypt this.
 *
 * Out is formatted:
 * 		out = [enc_msg_len | enc_msg | ct_len | ct ],
 * where enc_msg_len & ct_len are serialized 4 byte integers.
 *
 * @param[out] out		Byte array of encrypted payload and serialized ct
 * @param[out] out_len	The allocated size of out/returns used size of out
 * @param[in]  type		The type of the sensor measurement
 * @param[in]  data		The sensor measurement data
 * @return				An error code, 0 if successful
 */
int format_symm_enc_latest_key(uint8_t *out, int *out_len, char type, int data){
	uint8_t in[256], IV[BC_LEN] = {0};
	char tmp_str[256];
	int in_len, max_out = *out_len, err = 0;

	sprintf(tmp_str, "%c,%d,%d,%d", type, data, __enc_info->enc_time,
			__enc_info->ct_size);
	memcpy(in, tmp_str, strlen(tmp_str));
	in_len = strlen(tmp_str);

	print_byte_array(__enc_info->symm_key, 16);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, __enc_info->symm_key,
			128, IV);
	if (err != 0)
		return err;

	int_to_bytes(out, *out_len);
	*out_len += int_to_bytes(out + *out_len + 4, __enc_info->ct_size);
	memcpy(out + *out_len + 4, __enc_info->ct_buff, __enc_info->ct_size);
	*out_len += __enc_info->ct_size + 4;

	if (*out_len > max_out)
		err = -1;

	return err;
}

/*!
 * Updates the global structure __enc_info with a new symm key, ct, ct_size and
 * enc_time.
 *
 * @param[in] pol	Policy to encrypt under
 * @þaram[in] MA	Multi Authority if 1, 0 otherwise
 */
int update_enc_metadata(char *pol, int MA){
	xtimer_t xtimer;
	uint32_t enc_start, enc_end;
	int err = 0;

	enc_start = xtimer_now();
	if (MA){
		err = ma_gen_symm_key(__enc_info->symm_key, __enc_info->ct_buff,
				&(__enc_info->ct_size), pol);
	}else{
		err = cp_gen_symm_key(__enc_info->symm_key, __enc_info->ct_buff,
				&(__enc_info->ct_size), pol);
	}
	enc_end = xtimer_now();
	__enc_info->enc_time = (enc_end - enc_start)/1000;

	return err;
}


/*!
 * Generates a symmetric key via MA-ABE.
 *
 * @param[out] symm_key 		Buffer for key
 * @param[out] ct_buff			Allocated memory for serialized ciphertext
 * @param[out] ct_buff_len		Size of serialized ct
 * @return						Error code, 0 if successful
 */
int ma_gen_symm_key(uint8_t *symm_key, uint8_t *ct_buff, int *ct_buff_size,
		char *pol_str){
	int err;
	ma_global_params gp;
	auth_public_key pk;
	ma_ciphertext ct;
	fenc_attribute_policy pol;

	ma_set_global_params(&gp);
	ma_set_auth_pk(&pk, gp);

	err = gen_policy(&pol, pol_str);
	if (err != 0)
		return err;

	err = ma_encrypt(symm_key, &ct, gp, &pk, 1, pol);
	if (err != 0)
		return err;

	*ct_buff_size = maCT_to_bytes(ct_buff, ct);
	return err;
}

/*!
 * Generates a symmetric key via CP-ABE.
 *
 * @param[out] symm_key 	Buffer for key
 * @param[out] ct_buff		Allocated memory for serialized ciphertext
 * @param[out] ct_buff_len	Length of serialized ct
 * @return					Error code, 0 if successful
 */
int cp_gen_symm_key(uint8_t *symm_key, uint8_t *ct_buff, int *ct_buff_len,
		char *pol_str ){
	int err;
	fenc_public_params_WatersCP public_params;
	ciphertext_WatersCP	ct;

	cp_set_public_params(&public_params);
	err = cp_encrypt(symm_key, &ct, pol_str, public_params);
	if (err != 0)
		return err;

	*ct_buff_len = CT_to_bytes(ct_buff, ct);
	return err;
}

/*!
 * Put the data on the format "type,data,time,ciphertext_size" and then prepends
 * the length of this string in serialized format and then encrypts this.
 *
 * i.e. payload = [ser_len |"t,24,2342,1923"]
 *
 * @param[out] 	  out		A buffer containing encrypted data + serialized ct
 * @param[in/out] out_len	The size of the allocated out buffer, returns used
 * 							size.
 * @param[in]	  type		The type of sensor measurement
 * @param[in]	  data		The value of the sensor measurement
 * @param[in]	  MA		1 if Multi Authority, 0 otherwise
 * @param[in] 	  pol_str	The policy to encrypt under
 * @return					An error code, 0 at success
 */
int format_enc(uint8_t *out, int *out_len, char type, int data, int MA,
		char *pol_str){
	xtimer_t xtimer;
	uint32_t enc_start, enc_end, elapsed_ms;
	int max_out = *out_len, in_len, err = 0, ct_buff_len = 4096;
	uint8_t in[256], symm_key[16], ct_buff[4096], IV[BC_LEN] = {0};
	char tmp_str[256];

	enc_start = xtimer_now();
	if (MA)
		err = ma_gen_symm_key(symm_key, ct_buff,&ct_buff_len , pol_str);
	else
		err = cp_gen_symm_key(symm_key, ct_buff, &ct_buff_len , pol_str);

	if (err != 0)
		return err;

	enc_end = xtimer_now();
	elapsed_ms = (enc_end - enc_start)/1000;

	sprintf(tmp_str, "%c,%d,%d,%d", type, data, (int)elapsed_ms, ct_buff_len);
	memcpy(in, tmp_str, strlen(tmp_str));
	in_len = strlen(tmp_str);

	err = bc_aes_cbc_enc(out + 4, out_len, in, in_len, symm_key, 128, IV);
	int_to_bytes(out, *out_len);
	*out_len += int_to_bytes(out + *out_len + 4, ct_buff_len);
	memcpy(out + *out_len + 4, ct_buff, ct_buff_len);
	*out_len += ct_buff_len + 4;

	if (*out_len > max_out){
		printf("Error: The out buffer overflowed.\n");
		err = -1;
	}

	return err;
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

int format_decryption_check(uint8_t *data_ct, int MA){
	//init_abe_relic();
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
	str[out_len] = '\0';

	printf("xxOn format:'type,data,enc_time,ct_size'\n");
	printf("Dec string: %s\n", str);

	//clean_abe_relic();
	return err;
}

void* abe_thread(void *arg){
	init_abe_relic();

	uint8_t out[4096];
	int out_len = 4096, max_ct_size = 4096, data = 124;
	char type = 't';

	enc_metadata enc_data;
	__enc_info = &enc_data;

	while (1){
		update_enc_metadata("A1ONE and A1TWO", 0);
		if (__enc_info->ct_size > max_ct_size)
			printf("Buffer overflow for ct.\n");

		format_symm_enc_latest_key(out, &out_len, type, data);
		format_decryption_check(out, 0);
//		format_enc(out, &out_len, 't', 123, 0, "A1ONE and A1TWO");
//		format_decryption_check(out, 0);

	}

	clean_abe_relic();

	return NULL;
}
