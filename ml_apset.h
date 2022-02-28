/*
 * ml_apset.h
 *
 *  Created on: Nov 15, 2021
 *      Author: malafont
 */

#ifndef ML_APSET_H_
#define ML_APSET_H_

#include "psa/crypto.h"

#define KEY_SIZE_BITS 128 /* CCM blick size. */
#define KEY_SIZE (KEY_SIZE_BITS/8)
#define TAG_SIZE  16 /* can be 4, 6,8, 10, 12, 14, 16 */
#define NONCE_SIZE PSA_AEAD_NONCE_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CCM) /* [7:13] bytes */
#define NONCE_LEN 12
#define MESSAGE_SIZE 2048
#define CIPHER_SIZE (MESSAGE_SIZE + TAG_SIZE)
#define AD_BUF_SIZE TAG_SIZE

typedef struct ml_array_{
  uint8_t* data;
  size_t size;
  int len;
}ml_array_t;


ml_array_t* ml_array_new(size_t max_size);
int ml_array_reset(ml_array_t *array);
int ml_array_setup(uint8_t *buffer, size_t buffer_size, int buffer_len,ml_array_t *array);
int ml_array_copy(uint8_t *buffer, int buffer_len, ml_array_t *array);
int ml_array_alloc(ml_array_t *array, size_t size);
int ml_array_cleanup(ml_array_t *array);
int ml_array_destroy(ml_array_t *array);
int ml_array_print_hex_char(ml_array_t *array, const int columns_count);
int ml_array_print_char(ml_array_t *array, const int columns_count);
int ml_array_print_hex(ml_array_t *array, const int columns_count);





void clear_terminal_screen();
void print_buffer(uint8_t *array, int array_length);
void print_buffer_memory(const char* format, uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_hex_char(uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_hex(uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_char(uint8_t *array, int array_lenght, const int columns_count);
void print_key_hex(uint8_t *array, int array_length);

void print_key_attributes(psa_key_attributes_t *attributes);


psa_status_t create_random_key(ml_array_t *key_buffer, const size_t key_bytes);



psa_status_t create_cmac_hash_key(psa_key_id_t *key_id,
                                  ml_array_t *plain_key,
                                  ml_array_t *hash_key,
                                  psa_key_attributes_t *attr);

psa_status_t create_hmac_hash_key(psa_key_id_t *key_id,
                                  ml_array_t *plain_key,
                                  ml_array_t *hash_key,
                                  psa_key_attributes_t *attr);

psa_status_t calculate_mac_message(ml_array_t * message,
                                   psa_key_id_t key_id,
                                   psa_algorithm_t alg,
                                   ml_array_t *mac);


psa_status_t cmac_sign_message(ml_array_t *message, psa_key_id_t key_id, ml_array_t *mac);

psa_status_t message_cmac_authenticate(psa_key_id_t key_id, ml_array_t *message, ml_array_t *mac);
psa_status_t message_hmac_authenticate(psa_key_id_t key_id, ml_array_t *message, ml_array_t *mac);


psa_status_t apset_lab2a_cmac(char* message, size_t message_size);
psa_status_t apset_lab2a_hmac(char* message, size_t message_size);

psa_status_t apset_lab2b(char* message, size_t message_size);





#endif /* ML_APSET_H_ */
