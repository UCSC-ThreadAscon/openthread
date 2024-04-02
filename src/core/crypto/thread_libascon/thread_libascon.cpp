#include "crypto/thread_ascon.hpp"

void libascon_encrypt(uint8_t* ciphertext,
                      uint8_t* tag,
                      const uint8_t key[ASCON_AEAD128a_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data,
                      const uint8_t* plaintext,
                      size_t assoc_data_len,
                      size_t plaintext_len,
                      size_t tag_len)
{
#if LIBASCON_128A
  ascon_aead128a_encrypt(ciphertext, tag, key, nonce, assoc_data, plaintext,
                         assoc_data_len, plaintext_len, tag_len);
#elif LIBASCON_128
  ascon_aead128_encrypt(ciphertext, tag, key, nonce, assoc_data, plaintext,
                        assoc_data_len, plaintext_len, tag_len);
#endif
  return;
}

bool libascon_decrypt(uint8_t* plaintext,
                      const uint8_t key[ASCON_AEAD128a_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data,
                      const uint8_t* ciphertext,
                      const uint8_t* expected_tag,
                      size_t assoc_data_len,
                      size_t ciphertext_len,
                      size_t expected_tag_len)
{
#if LIBASCON_128A
  ascon_aead128a_decrypt(plaintext, key, nonce, assoc_data, ciphertext,
                         expected_tag, assoc_data_len, ciphertext_len,
                         expected_tag_len);
#elif LIBASCON_128
  ascon_aead128_decrypt(plaintext, key, nonce, assoc_data, ciphertext,
                         expected_tag, assoc_data_len, ciphertext_len,
                         expected_tag_len);
#endif
  return;
}