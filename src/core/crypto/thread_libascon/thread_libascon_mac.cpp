#include "crypto/thread_ascon.hpp"
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
  EmptyMemory(aNonce, ASCON_AEAD_NONCE_LEN);

  uint8_t sequenceNumber = GetSequence();

  uint8_t keyId = 0;
  if (GetKeyId(keyId) != OT_ERROR_NONE) {
    otLogCritPlat("Failed to get Key ID.");
  };

  uint32_t frameCounter = 0;
  if (GetFrameCounter(frameCounter) != OT_ERROR_NONE) {
    otLogCritPlat("Failed to use frame counter to create the nonce.");
  }

  uint8_t *offset = (uint8_t *) aNonce;

  memcpy(offset, &sequenceNumber, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  memcpy(offset, &keyId, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  BigEndian::WriteUint32(frameCounter, offset);

  return;
}

Error TxFrame::AsconDataEncrypt() {
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(GetAesKey(), key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(nonce);

  uint8_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t plaintextLength = GetPayloadLength();
  size_t assocDataLen = CRYPTO_ABYTES;

  libascon_encrypt(GetPayload(), GetFooter(), key, nonce, assocData,
                   GetPayload(), assocDataLen, plaintextLength,
                   tagLength);

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
}

Error RxFrame::AsconDataDecrypt(const KeyMaterial &aMacKey) {
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(aMacKey, key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(nonce);

  uint16_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t ciphertextLen = GetPayloadLength();
  size_t assocDataLen = CRYPTO_ABYTES;

  bool status = libascon_decrypt(GetPayload(), key, nonce, assocData,
                                 GetPayload(), GetFooter(), assocDataLen,
                                 ciphertextLen, tagLength);

  if (status == ASCON_TAG_INVALID) {
    otLogWarnPlat("Invalid ASCON ciphertext (LibAscon - MAC).");
    return OT_ERROR_SECURITY;
  }

  return OT_ERROR_NONE;
}

} // namespace Mac
} // namespace ot