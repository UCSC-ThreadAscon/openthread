#include "crypto/cse299a_ascon.hpp"
#include "thread_ascon_encryption_flags.h"

#include "openthread/platform/radio.h"
#include "mac/mac_frame.hpp"
#include "mac/mac_types.hpp"

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
  EmptyMemory(aAssocData, CRYPTO_ABYTES);

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

void Frame::CreateAsconNonce(void* aNonce) {
  EmptyMemory(aNonce, CRYPTO_NPUBBYTES);

  uint8_t sequenceNumber = GetSequence();

  uint8_t keyId = 0;
  if (GetKeyId(keyId) != OT_ERROR_NONE) {
    otLogCritPlat("Failed to get Key ID.");
  };

#if THREAD_ASCON_DEBUG
  otLogNotePlat("Sequence Number: %" PRIu8 "", sequenceNumber);
  otLogNotePlat("Key ID: %" PRIu8 "", keyId);
  otLogNotePlat("Footer Bits: %" PRIu32 "", ((uint32_t *) GetFooter())[0]);
#endif // THREAD_ASCON_DEBUG

  uint8_t *offset = (uint8_t *) aNonce;

  memcpy(offset, &sequenceNumber, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  memcpy(offset, &keyId, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  /**
   * AesCcm::Finalize() generates the nonces by grabbing THE FIRST 4 BYTES OF
   * THE FOOTER (i.e. GetFooterLength() - GetFcsSize() ). We do the same
   * when generating the Associated Data.
   *
   * Looking at Wireshark, I believe the first 4 bytes of the footer
   * is the MIC.
  */
  memcpy(offset, GetFooter(), GetFooterLength() - GetFcsSize());

  return;
}

Error TxFrame::AsconDataEncrypt() {
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(GetAesKey(), key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[CRYPTO_NPUBBYTES];
  CreateAsconNonce(nonce);

#if THREAD_ASCON_DEBUG
  AsconDebugPrint(key, nonce, assocData);
#endif // THREAD_ASCON_DEBUG

  uint8_t footerLength = GetFooterLength();
  uint8_t footerCopy[footerLength];
  memcpy(footerCopy, GetFooter(), footerLength);

  uint16_t plaintextLength = GetPayloadLength();
  unsigned long long ciphertextLength;

  unsigned long long expectedCipherLen = plaintextLength + CRYPTO_ABYTES;

  if (expectedCipherLen >= GetMaxPayloadLength()) {
    otLogWarnPlat("Ciphertext is too big - not going to use ASCON encryption.");
    return kErrorNoBufs;
  }

  SetPayloadLength(expectedCipherLen);

  void* end = GetPayload() + GetPayloadLength();
  memcpy(end, footerCopy, footerLength);

  crypto_aead_encrypt(GetPayload(), &ciphertextLength,
                      GetPayload(), plaintextLength,
                      assocData, CRYPTO_ABYTES,
                      NULL, nonce, key);

  OT_ASSERT(expectedCipherLen == ciphertextLength);

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
}

Error RxFrame::AsconDataDecrypt(const KeyMaterial &aMacKey) {
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(aMacKey, key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[CRYPTO_NPUBBYTES];
  CreateAsconNonce(nonce);

#if THREAD_ASCON_DEBUG
  AsconDebugPrint(key, nonce, assocData);
#endif // THREAD_ASCON_DEBUG

  uint8_t footerLength = GetFooterLength();
  uint8_t footerCopy[footerLength];
  memcpy(footerCopy, GetFooter(), footerLength);

  uint16_t ciphertextLength = GetPayloadLength();
  unsigned long long plaintextLength;
  uint8_t plaintextBuffer[ciphertextLength - CRYPTO_ABYTES];

  int status = crypto_aead_decrypt(plaintextBuffer, &plaintextLength, NULL,
                                   GetPayload(), ciphertextLength,
                                   assocData, CRYPTO_ABYTES,
                                   nonce, key);
  if (status == -1) {
    otLogWarnPlat("Invalid ASCON ciphertext (MAC).");
    return OT_ERROR_SECURITY;
  }

  memcpy(GetPayload(), plaintextBuffer, plaintextLength);
  SetPayloadLength(plaintextLength);

  void* end = GetPayload() + GetPayloadLength();
  memcpy(end, footerCopy, footerLength);

  return OT_ERROR_NONE;
}

} // namespace Mac
} // namespace ot