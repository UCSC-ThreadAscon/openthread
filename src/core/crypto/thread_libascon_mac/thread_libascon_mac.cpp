#include "crypto/thread_ascon.hpp"
#include "thread_ascon_encryption_flags.h"

#include "openthread/platform/radio.h"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"

#include "hexdump.hpp"

#include <inttypes.h>

void ConvertToAsconKey(const ot::Mac::KeyMaterial &aMacKey, void *asconKey) {
  ot::Crypto::Key cryptoKey;
  aMacKey.ConvertToCryptoKey(cryptoKey);
  if (cryptoKey.GetBytes() == NULL) {
    otLogCritPlat("Failed to get Thread network key.");
  }

  EmptyMemory(asconKey, OT_NETWORK_KEY_SIZE);
  memcpy(asconKey, cryptoKey.GetBytes(), OT_NETWORK_KEY_SIZE);

  return;
}

namespace ot
{
namespace Mac
{

uint8_t* Frame::AddAddrToAd(Address addr, uint8_t* offset) {
  if (addr.GetType() == Mac::Address::kTypeExtended) // 8 bytes
  {
    Mac::ExtAddress ext = addr.GetExtended();
    memcpy(offset, ext.m8, sizeof(Mac::ExtAddress));
    offset += sizeof(Mac::ExtAddress);
  }
  else if (addr.GetType() == Mac::Address::kTypeShort) // 2 bytes
  {
    Mac::ShortAddress shortAddr = addr.GetShort();
    memcpy(offset, &shortAddr, sizeof(Mac::ShortAddress));
    offset += sizeof(Mac::ShortAddress);
  }
  else
  {
    otLogCritPlat("Failed to get address to be used in the nonce.");
  }
  return offset;
}

void Frame::CreateAssocData(void *aAssocData) {
  EmptyMemory(aAssocData, ASSOC_DATA_BYTES);

  Address dst; EmptyMemory(&dst, sizeof(Address));
  if (GetDstAddr(dst) != OT_ERROR_NONE) {
    otLogCritPlat("Failed to get destination address.");
  }

  Address src; EmptyMemory(&src, sizeof(Address));
  if (GetSrcAddr(src) != OT_ERROR_NONE) {
    otLogCritPlat("Failed to get source address.");
  }

  uint8_t* offset = (uint8_t *) aAssocData;
  offset = AddAddrToAd(dst, offset);
  offset = AddAddrToAd(src, offset);

  return;
}

/**
 * Generates the nonce to be used in ASCON AEAD. The nonce
 * that is created follows the 802.15.4-2006 Specification,
 * page 213.
 *
 * 802.15.4-2006 (pg. 213) state that the nonce is as follows:
 *
 *  | Extended Address | Frame Counter | Security Level |
 *
 * @param[in] aExtAddress: the 802.15.4 Source Extended Address
 * @param[in] frameCounter: the Frame Counter from the MAC header
 * @param[in] securityLevel: the Security Level from the Aux Security Header
 * @param[out] aNonce: The pointer to the nonce.
*/
void CreateAsconNonce(const ExtAddress &aExtAddress,
                      uint32_t frameCounter,
                      uint8_t securityLevel,
                      void* aNonce)
{
  EmptyMemory(aNonce, ASCON_AEAD_NONCE_LEN);

  uint8_t *offset = (uint8_t *) aNonce;

  memcpy(offset, aExtAddress.m8, sizeof(Mac::ExtAddress));
  offset += sizeof(Mac::ExtAddress);

  BigEndian::WriteUint32(frameCounter, offset);
  offset += sizeof(uint32_t);

  memcpy(offset, &securityLevel, sizeof(uint8_t));
  return;
}

/**
 * We got the idea to repeat the 128 bit network key twice to create a 256 bit key from:
 * 
 * - Daniel J. Bernstein, who does the same to obtain a 256 bit key from a 128 bit key
 *   for Salsa20: https://cr.yp.to/snuffle/keysizes.pdf
 * 
 *   We initially learned about Bernstein's stratey from the following Stack Exchange user
 *   DerekKnowles's Crypto Stack Exchange post:
 *   https://crypto.stackexchange.com/a/113638
 * 
 * - Stack Exchange user DannyNiu also suggested this idea as well in their
 *   Crypto Stack Exchange post:
 *   https://crypto.stackexchange.com/a/113588
 */
void createChaChaPolyKey(const ot::Mac::KeyMaterial &aMacKey, unsigned char *key)
{
  EmptyMemory(key, CHACHAPOLY_KEY_LEN);
  ConvertToAsconKey(aMacKey, key);
  return;
}

Error TxFrame::AsconDataEncrypt(const ExtAddress &aExtAddress,
                                uint32_t frameCounter,
                                uint8_t securityLevel)
{
#if ASCON_AEAD_128
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(GetAesKey(), key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");
#endif

  uint8_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t plaintextLength = GetPayloadLength();
  size_t assocDataLen = ASSOC_DATA_BYTES;

  unsigned long long ciphertextLength;

  uint8_t buffer[plaintextLength + tagLength];
  EmptyMemory(buffer, sizeof(buffer));

  crypto_aead_encrypt(buffer, &ciphertextLength,
                      GetPayload(), plaintextLength,
                      assocData, assocDataLen, NULL, nonce, key);

  assert(ciphertextLength == (plaintextLength + tagLength));

  // Add ciphertext as payload, the ASCON tag to the MIC.
  memcpy(GetPayload(), buffer, plaintextLength);
  memcpy(GetFooter(), buffer + plaintextLength, tagLength);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  // Length of plaintext and ciphertext (without tag) are the same under ASCON AEAD.
  hexDump((void *) GetPayload(), plaintextLength, "Ciphertext Bytes (no tag)");
  hexDump((void *) GetFooter(), tagLength, "Tag (Footer) Bytes");
#endif

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
#elif CHA_CHA_POLY
  unsigned char key[CHACHAPOLY_KEY_LEN];
  createChaChaPolyKey(GetAesKey(), key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char asconNonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, asconNonce);

  // ChaChaPoly nonce is first 12 bytes of ASCON Nonce.
  unsigned char nonce[CHACHAPOLY_NONCE_LEN];
  EmptyMemory(nonce, CHACHAPOLY_NONCE_LEN);
  memcpy(nonce, asconNonce, CHACHAPOLY_NONCE_LEN);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) key, CHACHAPOLY_KEY_LEN, "Thread Network Key Bytes");
  hexDump((void *) nonce, CHACHAPOLY_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");
#endif

  uint16_t plaintextLength = GetPayloadLength();

  uint8_t* plaintextBuffer[plaintextLength];
  EmptyMemory(plaintextBuffer, plaintextLength);
  memcpy(plaintextBuffer, GetPayload(), plaintextLength);

  SetPayloadLength(GetPayloadLength() + CHACHAPOLY_TAG_LEN);

  uint8_t footerLength = GetFooterLength();
  uint8_t footerCopy[footerLength];
  memcpy(footerCopy, GetFooter(), footerLength);

  void* end = GetPayload() + GetPayloadLength();
  memcpy(end, footerCopy, footerLength);

  uint8_t tag[CHACHAPOLY_TAG_LEN];
  EmptyMemory(tag, CHACHAPOLY_TAG_LEN);

  mbedtls_chachapoly_context context;
  EmptyMemory(&context, sizeof(mbedtls_chachapoly_context));

  mbedtls_chachapoly_init(&context);
  mbedtls_chachapoly_setkey(&context, key);

  mbedtls_chachapoly_encrypt_and_tag(&context, plaintextLength, nonce, assocData,
                                     ASSOC_DATA_BYTES, plaintextBuffer, GetPayload(), tag);

  end = GetPayload() + plaintextLength;
  memcpy(end, tag, CHACHAPOLY_TAG_LEN);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) GetPayload(), plaintextLength, "Ciphertext Bytes (no tag)");
  hexDump((void *) tag, CHACHAPOLY_TAG_LEN, "Tag (Footer) Bytes");
#endif

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
#else // LIBASCON
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(GetAesKey(), key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");
#endif

  uint8_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t plaintextLength = GetPayloadLength();
  size_t assocDataLen = ASSOC_DATA_BYTES;

  libascon_encrypt(GetPayload(), GetFooter(), key, nonce, assocData,
                   GetPayload(), assocDataLen, plaintextLength,
                   tagLength);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  // Length of plaintext and ciphertext (without tag) are the same under ASCON AEAD.
  hexDump((void *) GetPayload(), plaintextLength, "Ciphertext Bytes (no tag)");
  hexDump((void *) GetFooter(), tagLength, "Tag (Footer) Bytes");
#endif

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
#endif
}

Error RxFrame::AsconDataDecrypt(const KeyMaterial &aMacKey,
                                const ExtAddress &aExtAddress,
                                uint32_t frameCounter,
                                uint8_t securityLevel)
{
#if ASCON_AEAD_128
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(aMacKey, key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

#if ASCON_MAC_DECRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");

  // Ciphertext before it gets decrypted to plaintext in place.
  hexDump((void *) GetPayload(), GetPayloadLength(), "Ciphertext Bytes (no tag)");
#endif

  uint16_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t ciphertextLength = GetPayloadLength();
  size_t assocDataLen = ASSOC_DATA_BYTES;

  uint8_t ciphertextTag[ciphertextLength + tagLength];
  EmptyMemory(ciphertextTag, sizeof(ciphertextTag));

  // Add ciphertext + tag in single byte sequence.
  memcpy(ciphertextTag, GetPayload(), ciphertextLength);
  memcpy(ciphertextTag + ciphertextLength, GetFooter(), tagLength);

  unsigned long long plaintextLength;
  int status = crypto_aead_decrypt(GetPayload(), &plaintextLength, NULL,
                                   ciphertextTag, sizeof(ciphertextTag),
                                   assocData, assocDataLen, nonce, key);
  assert(plaintextLength == ciphertextLength);

#if ASCON_MAC_DECRYPT_HEX_DUMP
  // Length of plaintext and ciphertext (without tag) are the same under ASCON AEAD.
  hexDump((void *) GetPayload(), ciphertextLength, "Plaintext Bytes (no tag)");
  hexDump((void *) GetFooter(), tagLength, "Tag (Footer) Bytes");
#endif

  if (status != 0) {
    otLogWarnPlat("Invalid ASCON ciphertext (MAC).");
    return OT_ERROR_SECURITY;
  }

  return OT_ERROR_NONE;
#elif CHA_CHA_POLY
  unsigned char key[CHACHAPOLY_KEY_LEN];
  createChaChaPolyKey(aMacKey, key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char asconNonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, asconNonce);

  // ChaChaPoly nonce is first 12 bytes of ASCON Nonce.
  unsigned char nonce[CHACHAPOLY_NONCE_LEN];
  EmptyMemory(nonce, CHACHAPOLY_NONCE_LEN);
  memcpy(nonce, asconNonce, CHACHAPOLY_NONCE_LEN);

#if ASCON_MAC_DECRYPT_HEX_DUMP
  hexDump((void *) key, CHACHAPOLY_KEY_LEN, "Thread Network Key Bytes");
  hexDump((void *) nonce, CHACHAPOLY_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");

  // Ciphertext before it gets decrypted to plaintext in place.
  hexDump((void *) GetPayload(), GetPayloadLength(), "Ciphertext Bytes (with tag)");
#endif

  uint8_t footerLength = GetFooterLength();
  uint8_t footerCopy[footerLength];
  memcpy(footerCopy, GetFooter(), footerLength);

  uint16_t plaintextLength = GetPayloadLength();
  uint8_t* tag = GetPayload() + plaintextLength;

  mbedtls_chachapoly_context context;
  EmptyMemory(&context, sizeof(mbedtls_chachapoly_context));

  mbedtls_chachapoly_init(&context);
  mbedtls_chachapoly_setkey(&context, key);

  int status = mbedtls_chachapoly_auth_decrypt(&context, plaintextLength, nonce, assocData,
                                               ASSOC_DATA_BYTES, tag, GetPayload(),
                                               GetPayload());

#if ASCON_MLE_DECRYPT_HEX_DUMP
  hexDump((void *) GetPayload(), plaintextLen, "Plaintext Bytes (no tag)");
  hexDump((void *) tag, CHACHAPOLY_TAG_LEN, "MAC Tag Bytes");
#endif

  if (!CHACHAPOLY_VALID(status)) {
    if (status == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED)
    {
      otLogWarnPlat("Invalid ChaChaPoly Ciphertext (MAC): Auth Failed.");
    }
    else if (status == MBEDTLS_ERR_CHACHAPOLY_BAD_STATE)
    {
      otLogWarnPlat("Invalid ChaChaPoly Ciphertext (MAC): Bad State.");
    }
    else
    {
      otLogWarnPlat("Invalid ChaChaPoly Ciphertext (MAC).");
    }
    return OT_ERROR_SECURITY;
  }

  SetPayloadLength(plaintextLength);

  void* end = GetPayload() + GetPayloadLength();
  memcpy(end, footerCopy, footerLength);

  return OT_ERROR_NONE;
#else // LIBASCON
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(aMacKey, key);

  unsigned char assocData[ASSOC_DATA_BYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

#if ASCON_MAC_DECRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, ASSOC_DATA_BYTES, "Associated Data Bytes");

  // Ciphertext before it gets decrypted to plaintext in place.
  hexDump((void *) GetPayload(), GetPayloadLength(), "Ciphertext Bytes (no tag)");
#endif

  uint16_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t ciphertextLength = GetPayloadLength();
  size_t assocDataLen = ASSOC_DATA_BYTES;

  bool status = libascon_decrypt(GetPayload(), key, nonce, assocData,
                                 GetPayload(), GetFooter(), assocDataLen,
                                 ciphertextLength, tagLength);

#if ASCON_MAC_DECRYPT_HEX_DUMP
  // Length of plaintext and ciphertext (without tag) are the same under ASCON AEAD.
  hexDump((void *) GetPayload(), ciphertextLength, "Plaintext Bytes (no tag)");
  hexDump((void *) GetFooter(), tagLength, "Tag (Footer) Bytes");
#endif

  if (status == ASCON_TAG_INVALID) {
    otLogWarnPlat("Invalid ASCON ciphertext (LibAscon - MAC).");
    return OT_ERROR_SECURITY;
  }

  return OT_ERROR_NONE;
#endif
}

} // namespace Mac
} // namespace ot