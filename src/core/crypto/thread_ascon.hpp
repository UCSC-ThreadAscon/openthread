#ifndef THREAD_ASCON_HPP_
#define THREAD_ASCON_HPP_

#include "thread_ascon_encryption_flags.h"

#if ASCON_128A_ESP32
#include "crypto/ascon128av12_esp32/api.hpp"
#endif

#if ASCON_128A_REF
#include "crypto/ascon128av12_ref/api.hpp"
#endif

// #if LIBASCON_128A
#include "crypto/libascon/ascon.h"
#include "crypto/libascon/ascon_internal.h"
// #endif

#include "crypto/aes_ccm.hpp"
#include "error.h"

#include <openthread/logging.h>

/**
 * Took the `CRYPTO_ABYTES` macro definition from the `api.h` header, which is
 * the same in all ASCON C implementations:
 * https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128av12/ref/api.h
*/
#define CRYPTO_ABYTES 16

/**
 * Empties all memory for `size` bytes starting at memory address `pointer`.
 *
 * @param[in] pointer: the pointer of the stack memory
 * @param[in] size:    the size of the memory that `pointer` points to
 *
 * I got the idea to use `memset()` to clear stack memory from
 * the Google Search AI:
 * https://docs.google.com/document/d/1o-NaEOA-vzWPCv7VX1dONUfwos2epveDk4H_Y2Y5g1Y/edit?usp=sharing
*/
#define EmptyMemory(pointer, size) memset((void *) pointer, 0, size)

/**
 * Converts an AES network key object to 16-byte key that can be used with
 * the ASCON cipher.
 *
 * @param[in] aMacKey: the Thread Network Key
 * @param[out] asconKey: the pointer to the place in memory to set the ASCON key
 *
 * @retval keyPtr: the pointer to the network key, or NULL if failed to
 *                 obtain it.
*/
void ConvertToAsconKey(const ot::Mac::KeyMaterial &aMacKey,
                       void* asconKey);

/**
 * Debugging function that prints to the serial monitor the bytes of
 * the key, nonce, and associated data as C strings.
 *
 * @param[in] key: the ASCON key used for encryption
 * @param[in] nonce: the nonce to be used in encryption
 * @param[in] assocData: the associated data
*/
#define AsconDebugPrint(key, nonce, assocData)                                   \
  otLogNotePlat("Key: %" PRIu64 "", ((uint64_t *) key)[0]);                      \
  otLogNotePlat("Associated Data: %" PRIu64 "", ((uint64_t *) assocData)[0]);    \
  otLogNotePlat("Nonce: %" PRIu64 "", ((uint64_t *) nonce)[0]);                  \

/**
 * The encryption function prototype for the ASCON C reference implementations.
 *
 * For the source code behind this function, visit:
 * https://github.com/ascon/ascon-c
*/
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k);


/**
 * The decryption function prototype for the ASCON C reference implementations.
 *
 * For the source code behind this function, visit:
 * https://github.com/ascon/ascon-c
*/
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k);

#endif // THREAD_ASCON_HPP_