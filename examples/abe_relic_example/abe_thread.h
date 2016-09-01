/*
 * abe_thread.h
 *
 *  Created on: Aug 31, 2016
 *      Author: joakim
 */

#ifndef EXAMPLES_ABE_RELIC_EXAMPLE_ABE_THREAD_H_
#define EXAMPLES_ABE_RELIC_EXAMPLE_ABE_THREAD_H_

typedef struct _enc_info{
	char 	type;						// type of sensor measurement
	int 	data;						// sensor measurement
	int		MA;							// 0 for single authority, 1 otherwise
	char    pol_str[MAX_POLICY_STR];	// policy to encrypt under
}enc_info;

typedef struct _enc_metadata{
	uint8_t symm_key[16];
	uint8_t ct_buff[4096];
	int 	ct_size;
	int 	enc_time;
}enc_metadata;

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
int format_symm_enc_latest_key(uint8_t *out, int *out_len, char type, int data);

/*!
 * Updates the global structure __enc_info with a new symm key, ct, ct_size and
 * enc_time.
 *
 * @param[in] pol	Policy to encrypt under
 * @þaram[in] MA	Multi Authority if 1, 0 otherwise
 */
int update_enc_metadata(char *pol, int MA);

/*!
 * Generates a symmetric key via MA-ABE.
 *
 * @param[out] 	  symm_key 		Buffer for key
 * @param[out]	  ct_buff		Allocated memory for serialized ciphertext
 * @param[in/out] ct_buff_len	Size of the allocated ct_buff, returns used size
 * @return						Error code, 0 if successful
 */
int ma_gen_symm_key(uint8_t *symm_key, uint8_t *ct_buff, int *ct_buff_size,
		char *pol_str);

/*!
 * Generates a symmetric key via CP-ABE.
 *
 * @param[out] 	  symm_key 		Buffer for key
 * @param[out]	  ct_buff		Allocated memory for serialized ciphertext
 * @param[in/out] ct_buff_len	Size of the allocated ct_buff, returns used size
 * @return						Error code, 0 if successful
 */
int cp_gen_symm_key(uint8_t *symm_key, uint8_t *ct_buff, int *ct_buff_len,
		char *pol_str );

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
		char *pol_str);

void* abe_thread(void *arg);

#endif /* EXAMPLES_ABE_RELIC_EXAMPLE_ABE_THREAD_H_ */
