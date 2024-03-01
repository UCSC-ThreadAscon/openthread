#ifndef CSE299A_ASCON_HPP_
#define CSE299A_ASCON_HPP_

#include "cse299a_encryption_flags.h"

#include "crypto/ascon_crypto_aead.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/ascon_api.hpp"
#include "error.h"

#include <openthread/logging.h>

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
 * @param[in] aMacKey: the Thread Network key
 * @param[out] asconKey: the pointer to the place in memory to set the ASCON key
 *
 * @retval keyPtr: the pointer to the network key, or NULL if failed to
 *                 obtain it.
*/
void ConvertToAsconKey(const ot::Mac::KeyMaterial &aMacKey,
                       void* asconKey);

/**
 * Displays a warning if the ASCON ciphertext is bigger than the
 * maximum link layer payload size.
 *
 * @param[in] payloadLen: the length of the encrypted payload
 * @param[in] maxPayloadLen: the maximum length of the link layer payload.
*/
#define ExceedMaxPayloadSize(payloadLen, maxPayloadLen)           \
    if (payloadLen >= maxPayloadLen) {                            \
      otLogCritPlat("Payload is bigger than max payload size.");  \
    }                                                             \

#endif // CSE299A_ASCON_HPP_