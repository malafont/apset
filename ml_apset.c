/*
 * ml_apset.c
 *
 *  Created on: Nov 15, 2021
 *      Author: malafont
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ml_apset.h"

#include "psa/crypto.h"

#define COLUMN_PRINT 16





/************************************
 *  Global variable
 */

//








int char_occurance_count(const char* str, const char ch);

void print_buffer_memory_header(const int columns_count);
void print_buffer_character(const char* format,  char ch);
void print_char_row(const char* format, char* row, int columns_count);



int char_occurance_count(const char* str, const char ch)
{
  int count = 0;
  char *ret = (char*) str;
  while(*ret != '\0'){
      ret = memchr(ret, ch, strlen(ret));
      if(*ret == ch){
        count++;
      ret++;
      }
  }
  return count;
}

void print_buffer_character(const char* format, char ch)
{
  int count = char_occurance_count(format, '%');
  switch(count){
    case 1:
      printf(format,ch);
      break;
    case 2:
      printf(format,ch,ch);
      break;
    default:
      break;
  }
}

void print_char_row(const char* format, char* row, int columns_count)
{
  for (int i=0; i< columns_count; i++){
      print_buffer_character(format, *(row+i));
  }
}

/*
 * Print a non zero terminated buffer values in hex.
 */

void print_buffer(uint8_t *array, int array_length)
{
  int i;
  for(i=0; i< array_length; i++){
      printf("0x%02X", (unsigned int) (array[i]&0xFF));
      if(i+1 < array_length)
         printf(", ");
  }

}

void print_buffer_memory_header(const int columns_count)
{
  printf("\r\nAddress \t");
  for(int i=0; i<columns_count; i++){
      printf("[%2X]    ", i);
  }
  printf("\r\n");
}

void print_buffer_memory(const char *format, uint8_t *array, int array_lenght, const int columns_count)
{
  uint8_t *end = array + array_lenght;

  print_buffer_memory_header(columns_count);
  while(array < end){
      printf("%X:\t", (unsigned int)array);
      print_char_row(format, (char*)array, columns_count);
      printf("\r\n");
      array += columns_count;
  }
}

void print_buffer_memory_hex_char(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("\"%c\"[%2X] ", array, array_lenght, columns_count);
}

void print_buffer_memory_hex(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("[%2X]    ", array, array_lenght, columns_count);
}

void print_buffer_memory_char(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("\"%c\"     ", array, array_lenght, columns_count);
}

void print_key_hex(uint8_t *array, int array_length)
{
  for(int i=0; i<array_length; i++){
      printf("%02X", array[i]);
      if (i < array_length-1)
        printf("-");
  }
}


/*****************************************
 * Create a news ml_array_t object.
 * @param max_size  Maximum size of the array.
 * @return  reference to created array
 * if returned reference is null then there is not enough memory to create the object.
 * if object->data is null then there is not enough meory to create the array itself.
 */
ml_array_t* ml_array_new(size_t max_size)
{
  ml_array_t * new = (ml_array_t*) calloc(1, sizeof(ml_array_t));
  if(new){
      new->data = calloc(max_size, sizeof(uint8_t));
      if(new->data){
          new->size = max_size;
      }
  }
  return new;
}

/*****************
 * Reset an pre-initialize array.
 * @param array  Reference to ml_array_t to reset
 * return error code.
 * 0 - no error
 * -1-  Invalid array object.
 */
int ml_array_reset(ml_array_t *array)
{
  if(!array) return -1;
  memset(array->data, 0x0, array->size);
  return 0;
}

/******************
 * Fill information for a given buffer.
 * @param buffer        buffer to store information.
 * @param buffer_size
 * @param buffer_len    Number of valid element in buffer.
 * @param array         Array to initialize.
 * @return error code
 *  0- no error.
 *  -1- Invalid array object.
 *  -2- Invalid Buffer object.
 */
int ml_array_setup(uint8_t *buffer, size_t buffer_size, int buffer_len,ml_array_t *array)
{
  if (!array) return -1;
  if (!buffer) return -2;
  array->data = buffer;
  array->size = buffer_size;
  array->len = buffer_len;
  return 0;
}

/****************
 * copy a fuffer to array.
 * @param buffer        Reference to buffer to copy.
 * @param buffer_len    Length of character to copy.
 * @param array         Array to copy to.
 * @return error code
 * 0- No error
 * -1- The buffer is too large to fit in array.
 *
 */
int ml_array_copy(uint8_t *buffer, int buffer_len, ml_array_t *array)
{
  if (buffer_len > (int)(array->size-1)) return -1;
  memcpy(array->data, buffer, buffer_len);
  array->len = buffer_len;
  return 0;
}

/***********************************************
 * Memorry allocation for the array.  the Array need to be clean, by this data = 0
 *
 * @param array  Array to initialise.
 * @param size   Maximum array size.
 *
 * @return error code
 * 0- no error
 * -1-  Array data already been initialize and should be clean before reallocating memory.
 */
int ml_array_alloc(ml_array_t *array, size_t size)
{
   if (array->data != 0) return -1;
   array->data = calloc(size, sizeof(uint8_t));
   array->size = size;
   array->len = 0;
   return 0;
}

/******************************
 * Clean memory allocated for the array.
 * @param array   Array object to free.
 * @return error code
 * 0- no error
 * -1-  Invalid array object.
 * -2-  No resources to free.
 */
int ml_array_cleanup(ml_array_t *array)
{
  if(!array) return -1;
  if(!array->data) return -2;
  free(array->data);
  array->size = 0;
  array->len = 0;
  return 0;
}

/******************************
 * destroy an ml_array_t object with deallocating resources.
 * @param array reference to object to clean.
 * @return Always 0;
 */
int ml_array_destroy(ml_array_t *array)
{
  if (array){
      ml_array_cleanup(array);
      free(array);
  }
  return 0;
}


int ml_array_print_hex_char(ml_array_t *array, const int columns_count)
{
  if(!array) return -1;
  print_buffer_memory_hex_char(array->data, array->len, columns_count);
  return 0;
}
int ml_array_print_char(ml_array_t *array, const int columns_count)
{
  if(!array) return -1;
  if(!array->data) return -2;
  print_buffer_memory_char(array->data, array->len, columns_count);
  return 0;
}
int ml_array_print_hex(ml_array_t *array, const int columns_count)
{
  if(!array) return -1;
  if(!array->data) return -2;
  print_buffer_memory_hex(array->data, array->len, columns_count);
  return 0;
}






/*
 * Print the key attributes values.
 */
void print_key_attributes(psa_key_attributes_t *attributes)
{
  printf("{type: 0x%X, bits: 0X%X, lifetime: 0x%X, id: 0x%X, alg: 0x%X, alg2: 0x%X, usage: 0x%X, flags: 0x%X}",
         attributes->private_core.private_type,
         attributes->private_core.private_bits,
         (unsigned int)attributes->private_core.private_lifetime,
         (unsigned int)attributes->private_core.private_id,
         (unsigned int)attributes->private_core.private_policy.private_alg,
         (unsigned int)attributes->private_core.private_policy.private_alg2,
         (unsigned int)attributes->private_core.private_policy.private_usage,
         attributes->private_core.private_flags);
}

void clear_terminal_screen()
{
  for(int i=0; i<80; i++)
     printf("\n");
}

/*******************************************************
 * Create a random key
 * @param buffer  Location where to store the key.
 * @param buffer_length Length of the buffer to store the generated key (byte).
 * @param key_bytes  Number of bytes of the key to generate.
 * @return error code.  PSA_SUCCESS return if successful.
 */
psa_status_t create_random_key(ml_array_t *buffer, const size_t key_bytes)
{
  psa_status_t ret = PSA_SUCCESS;
  buffer->len = 0;
  if (!buffer) return PSA_ERROR_INVALID_ARGUMENT;
  if (buffer->size < key_bytes) return PSA_ERROR_INSUFFICIENT_MEMORY;
  ret = psa_crypto_init();
  if (ret == PSA_SUCCESS)
    ret = psa_generate_random(buffer->data, key_bytes);
  if (ret == PSA_SUCCESS)
    buffer->len =(int)key_bytes;

  return ret;
}


psa_status_t ml_setup_mac_attributes(psa_key_attributes_t *attr, psa_key_type_t type, psa_algorithm_t algo, unsigned int bits)
{
  psa_status_t ret = psa_crypto_init();
  if(ret == PSA_SUCCESS){


  *attr = psa_key_attributes_init();
  psa_set_key_type(attr, type);
  psa_set_key_bits(attr, bits);
  psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH|PSA_KEY_USAGE_VERIFY_MESSAGE|PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(attr, algo);

  }
  return ret;
}

psa_status_t ml_setup_cmac_attributes(psa_key_attributes_t *attr, unsigned int bits)
{
  return ml_setup_mac_attributes(attr, PSA_KEY_TYPE_AES, PSA_ALG_CMAC, bits);
}

psa_status_t ml_setup_hmac_attributes(psa_key_attributes_t *attr, unsigned int bits)
{
  return ml_setup_mac_attributes(attr,PSA_KEY_TYPE_HMAC, PSA_ALG_HMAC(PSA_ALG_SHA_256), bits);
}


psa_status_t create_mac_key(psa_key_id_t *key_id,
                            unsigned int key_len_bits,
                            ml_array_t * plain_key,
                            ml_array_t * hash_key,
                            psa_key_type_t key_type,
                            psa_key_attributes_t *attr,
                            psa_algorithm_t algo
                            )
{
  psa_status_t ret;

  if (!plain_key) return PSA_ERROR_INVALID_ARGUMENT;
  if (!hash_key) return PSA_ERROR_INVALID_ARGUMENT;
  ret = create_random_key(plain_key,  key_len_bits/8);
  if (ret == PSA_SUCCESS){
      printf("\r\nPlaintext key (%d): ", plain_key->len);
      print_key_hex(plain_key->data, plain_key->len);

      ret = psa_hash_compute(PSA_ALG_SHA_256, plain_key->data, plain_key->len, hash_key->data, hash_key->size, (size_t*) &hash_key->len);
      if(ret == PSA_SUCCESS){
          printf("\r\nHash Key (%d): ", hash_key->len);
          print_key_hex(hash_key->data, hash_key->len);


          ret = ml_setup_mac_attributes(attr,
                                  key_type,
                                  algo,
                                  key_len_bits);
          if ( ret == PSA_SUCCESS){

              ret = psa_import_key(attr,  hash_key->data, hash_key->len, key_id);
              if(ret == PSA_SUCCESS){
                  printf("\r\nGenerate key #%ld",*key_id);
                  printf("\r\nKey Attributes: ");
                  print_key_attributes(attr);
              }
              else{
                  printf("\r\nError #%d: fail to import key", (int)ret);
              }

          }
          else{
              printf("\r\nError #%d: fail to set attributes", (int) ret);
          }

      }
      else
        printf("\r\nError #%d: fail to hash key", (int)ret);
  }
  else
    printf("\r\nError $%d: fail to create plaintext key", (int)ret);
  return ret;
}


psa_status_t create_cmac_hash_key(psa_key_id_t *key_id,
                                  ml_array_t *plain_key,
                                  ml_array_t *hash_key,
                                  psa_key_attributes_t *attr)
{
  printf("\r\n\nCreating CMAC random key: ");
  return create_mac_key(key_id,
                        256,
                        plain_key,
                        hash_key,
                        PSA_KEY_TYPE_AES,
                        attr,
                        PSA_ALG_CMAC);
}


psa_status_t create_hmac_hash_key(psa_key_id_t *key_id,
                                  ml_array_t *plain_key,
                                  ml_array_t *hash_key,
                                  psa_key_attributes_t *attr)
{
  printf("\r\n\nCreating HMAC random key: ");
  return create_mac_key(key_id,
                        hash_key->size *8,
                        plain_key,
                        hash_key,
                        PSA_KEY_TYPE_HMAC,
                        attr,
                        PSA_ALG_HMAC(PSA_ALG_SHA_256));
}

psa_status_t calculate_mac_message(ml_array_t * message,
                                   psa_key_id_t key_id,
                                   psa_algorithm_t alg,
                                   ml_array_t *mac)
{
  psa_status_t ret;
  psa_mac_operation_t mac_op = psa_mac_operation_init();
  ret = psa_mac_sign_setup(&mac_op, key_id, alg);
  if (ret == PSA_SUCCESS)
    ret = psa_mac_update(&mac_op, message->data, message->len);
  if (ret == PSA_SUCCESS)
    ret = psa_mac_sign_finish(&mac_op, mac->data, mac->size, (size_t*)&mac->len);
  if (ret != PSA_SUCCESS)
    psa_mac_abort(&mac_op);
  print_key_hex(mac->data, mac->len);
  return ret;
}


psa_status_t cmac_sign_message(ml_array_t *message, psa_key_id_t key_id, ml_array_t *mac)
{
  printf("\r\nMAC for CMAC: ");
  return calculate_mac_message(message, key_id, PSA_ALG_CMAC, mac);
}

psa_status_t calculate_hmac_message(ml_array_t *message, psa_key_id_t key_id, ml_array_t *mac){
  printf("\r\nMAC for HMAC: ");
  return calculate_mac_message(message, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), mac);
}

psa_status_t message_mac_authenticate(psa_key_id_t key_id, psa_algorithm_t alg, ml_array_t *message, ml_array_t *mac)
{
  psa_mac_operation_t operation;
  psa_status_t ret;
  operation = psa_mac_operation_init();

  ret = psa_mac_verify_setup(&operation, key_id, alg);
  if(ret == PSA_SUCCESS)
    ret = psa_mac_update(&operation, message->data, message->len); // do not use pas_mac_verify.
  if(ret == PSA_SUCCESS)
     ret = psa_mac_verify_finish(&operation, mac->data, mac->len);
  if (ret != PSA_SUCCESS)
    psa_mac_abort(&operation);
  return ret;
}


psa_status_t message_cmac_authenticate(psa_key_id_t key_id, ml_array_t *message, ml_array_t *mac)
{
  return message_mac_authenticate(key_id,PSA_ALG_CMAC,message, mac);
}

psa_status_t message_hmac_authenticate(psa_key_id_t key_id, ml_array_t *message, ml_array_t *mac)
{
  return message_mac_authenticate(key_id,PSA_ALG_HMAC(PSA_ALG_SHA_256), message, mac);
}

psa_status_t apset_lab2a_cmac(char* message, size_t message_size)
{
  psa_status_t ret;
  psa_key_id_t key_id;
  psa_key_attributes_t attr;
  ml_array_t msg;

  ml_array_t *key = ml_array_new(256/8);
  ml_array_t *hash = ml_array_new(256/8);
  ml_array_t *mac = ml_array_new(256/8);

  if( (key !=0) && (hash !=0) && (mac !=0)){
      ml_array_setup((uint8_t*)message, message_size, (int)message_size, &msg);

      //Initialise cmac key.
      printf("\r\n\nTesting the CMAC operation:");
      ret = create_cmac_hash_key(&key_id, key, hash, &attr);
      if (ret == PSA_SUCCESS){
          // Sign message.
          ret = cmac_sign_message(&msg, key_id, mac);
      }

      // In real life message is ready to TX.

      if(ret == PSA_SUCCESS){

          // Verify the message
          ret = message_cmac_authenticate(key_id, &msg, mac);
      }
      if(ret == PSA_SUCCESS)
        printf("\r\nMessage signature verification successful");
      else
        printf("\r\nMessage signature verification failed #%ld", ret);


      if(ret == PSA_SUCCESS)
        printf("\r\nYou wrote:\r\n%s ", message);
      psa_destroy_key(key_id);
      psa_reset_key_attributes(&attr);
    }
  ml_array_destroy(mac);
  ml_array_destroy(hash);
  ml_array_destroy(key);
  return ret;

}


psa_status_t apset_lab2a_hmac(char* message, size_t message_size)
{
  psa_status_t ret;
  psa_key_id_t key_id;
  psa_key_attributes_t attr;

  ml_array_t *key = ml_array_new(256/8);
  ml_array_t *hash = ml_array_new(256/8);
  ml_array_t *mac = ml_array_new(256/8);
  ml_array_t msg;
  if( (key !=0) && (hash !=0) && (mac !=0)){

      ml_array_setup((uint8_t*)message, message_size, (int)message_size, &msg);


      // HMAC
      printf("\r\n\nTesting the HMAC operation:");
      ret = create_hmac_hash_key(&key_id, key, hash, &attr);
      if (ret == PSA_SUCCESS){
          // Sign message.
          ret = calculate_hmac_message(&msg, key_id, mac);
      }

      if(ret == PSA_SUCCESS){

          // Verify the message
          ret = message_hmac_authenticate(key_id, &msg, mac);
      }

      if(ret == PSA_SUCCESS){
          printf("\r\nMessage signature verification successful");
          printf("\r\nYou wrote:\r\n%s ", message);

      }
      else
        printf("\r\nMessage signature verification failed #%ld", ret);
      psa_destroy_key(key_id);
      psa_reset_key_attributes(&attr);
    }
  ml_array_destroy(hash);
  ml_array_destroy(key);
  ml_array_destroy(mac);
  return ret;
}



psa_status_t ml_setup_aes_attributes(psa_key_attributes_t *attr, psa_algorithm_t algo)
{
  psa_status_t ret = psa_crypto_init();
  if (ret == PSA_SUCCESS){
      *attr = psa_key_attributes_init();
      psa_set_key_type(attr, PSA_KEY_TYPE_AES);
      psa_set_key_usage_flags(attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
      psa_set_key_algorithm(attr, algo);
  }
  return ret;
}

/*
 * Create AES CCM attributes
 * *attr    Reference to psa_key_attributes_t structure to fill.
 * bits     Key length in bits (128, 196, 256);
 */
psa_status_t ml_setup_aes_ccm_attributes(psa_key_attributes_t *attr)
{
  return ml_setup_aes_attributes(attr, PSA_ALG_CCM);
}

psa_status_t ml_setup_aes_gcm_attributes(psa_key_attributes_t *attr)
{
  return ml_setup_aes_attributes(attr, PSA_ALG_GCM);
}

/******************
 * Generate an initialisation vector.
 * @param buffer      Localisation to store iv.
 * @param buffer_len  Maximum size of iv vector.
 * @param iv_len      Length of desired iv vector shoudl be between [7:13] bytes.
 * @return PSA_SUCCESS if success full..
 *          PSA_ERROR_INVALID_ARGUMENT mean that iv_len is outside supported range.
 */
psa_status_t ml_generate_iv(ml_array_t *buffer, size_t iv_len)
{
  if (iv_len < 7) return PSA_ERROR_INVALID_ARGUMENT;
  if (iv_len >13) return PSA_ERROR_INVALID_ARGUMENT;
  psa_status_t ret = create_random_key(buffer, iv_len);
  if (ret == PSA_SUCCESS) {
      printf("\r\n%d bits IV vector: ", iv_len*8);
      print_key_hex(buffer->data, buffer->len);
  }
  return ret;
}


/*************************
 * Generate an crypto key.
 * @param buffer      buffer address to store key
 * @param buffer_len  size of the buffer.
 * @param key_len     size of the key to generate.
 * @return
 */
psa_status_t ml_generate_crypto_key(ml_array_t *buffer, size_t key_len)
{
  psa_status_t ret = create_random_key(buffer, key_len);
  if(ret == PSA_SUCCESS){
      printf("\r\nCrypto key of %d bits: ",key_len*8);
      print_key_hex(buffer->data, buffer->len);
  }
  return ret;
}


/*************************
 * Generate an authentication key.
 * @param buffer      buffer address to store key
 * @param buffer_len  size of the buffer.
 * @param key_len     size of the key to generate.
 * @return
 */
psa_status_t ml_generate_authentication_key(ml_array_t *buffer, size_t key_len)
{
  psa_status_t ret = create_random_key(buffer, key_len);
  if(ret == PSA_SUCCESS){
      printf("\r\nAuthentication key of %d bits: ",key_len*8);
      print_key_hex(buffer->data, buffer->len);
  }
  return ret;
}





psa_status_t apset_lab2b(char* message, size_t message_size)
{
  psa_key_id_t key_id;
  psa_key_attributes_t key_attr;

  ml_array_t msg;
  ml_array_t *decrypt_buf, *nonce_buf, *ad_buf, *cipher, *key;
  psa_status_t ret = ml_array_setup((uint8_t*)message, MESSAGE_SIZE, message_size, &msg);
  if (ret == PSA_SUCCESS){
      decrypt_buf = ml_array_new(MESSAGE_SIZE);
      nonce_buf = ml_array_new(NONCE_SIZE);
      ad_buf = ml_array_new(AD_BUF_SIZE);
      cipher = ml_array_new(CIPHER_SIZE);
      key = ml_array_new(KEY_SIZE);
      if( (decrypt_buf!= NULL) && (nonce_buf != NULL) && (ad_buf != NULL) && (cipher != NULL) && (key != NULL)){

          printf("\r\nMessage [%d bytes]:\r\n%s\r\n",message_size, message);
          print_buffer_memory_hex((uint8_t*)message, message_size, 16);
          if ((ret = psa_crypto_init()) == PSA_SUCCESS){
              ret = ml_generate_iv(nonce_buf, NONCE_SIZE);
              if(ret == PSA_SUCCESS){
                  ret = ml_generate_crypto_key(key,  KEY_SIZE);
                  if(ret == PSA_SUCCESS){
                      ret = ml_generate_authentication_key(ad_buf, TAG_SIZE);
                      if(ret == PSA_SUCCESS){
                          // Import a volatile plain key for AES CCM'
                          ret = ml_setup_aes_ccm_attributes(&key_attr);
                                  // Import a volatile plain key
                          ret = psa_import_key(&key_attr, key->data, key->len, &key_id);
                          if(ret == PSA_SUCCESS){
                              printf("\r\nGenerate key #%ld",key_id);
                              printf("\r\nKey Attributes: ");
                              print_key_attributes(&key_attr);

                              ret = psa_aead_encrypt(key_id,
                                                     PSA_ALG_CCM,
                                                     nonce_buf->data, nonce_buf->len,
                                                     ad_buf->data, ad_buf->len,
                                                     (uint8_t*)message, message_size,
                                                     cipher->data, cipher->size, (size_t*)&cipher->len);
                              if(ret == PSA_SUCCESS){
                                  printf("\r\n\nEncrypted message [%d bytes]:\r\n", cipher->len);
                                  print_buffer_memory_hex(cipher->data, cipher->len, 16);

                                  // AES CCM decryption
                                  ret = psa_aead_decrypt(key_id, PSA_ALG_CCM,
                                                         nonce_buf->data, nonce_buf->len,
                                                         ad_buf->data, ad_buf->len,
                                                         cipher->data, cipher->len,
                                                         decrypt_buf->data, decrypt_buf->size,
                                                         (size_t*)&decrypt_buf->len);
                                  if(ret == PSA_SUCCESS){
                                      printf("\r\n\ndecrypted message [%d bytes]:\r\n", decrypt_buf->len);
                                      print_buffer_memory_hex(decrypt_buf->data, decrypt_buf->len, 16);
                                      printf("\r\nMessage [%d bytes]:\r\n%s\r\n",decrypt_buf->len, decrypt_buf->data);
                                  }

                      }
                  }
              }

          }
      }
      else
        printf("Error with allocating memory buffers for the lab.");
      ml_array_destroy(decrypt_buf);
      ml_array_destroy(nonce_buf);
      ml_array_destroy(ad_buf);
      ml_array_destroy(cipher);
      ml_array_destroy(key);
  }




      }
    }
    else
      printf("\r\n Failed to import key.");

  // clean up
  psa_destroy_key(key_id);
  psa_reset_key_attributes(&key_attr);
  return ret;
}

