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

/**
 * Generates the nonce to be used in ASCON. The nonce
 * that is created follow the 802.15.4-2006 Specification,
 * page 213.
 *
 * 802.15.4-2006 (pg. 213) state that the nonce is as follows:
 *
 * | Extended Address | Frame Counter | Security Level |
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

Error TxFrame::AsconDataEncrypt(const ExtAddress &aExtAddress, uint32_t frameCounter, uint8_t securityLevel) {
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(GetAesKey(), key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, CRYPTO_ABYTES, "Associated Data Bytes");
#endif

  uint8_t tagLength = GetFooterLength() - GetFcsSize();
  uint16_t plaintextLength = GetPayloadLength();
  size_t assocDataLen = CRYPTO_ABYTES;

  libascon_encrypt(GetPayload(), GetFooter(), key, nonce, assocData,
                   GetPayload(), assocDataLen, plaintextLength,
                   tagLength);

#if ASCON_MAC_ENCRYPT_HEX_DUMP
  hexDump((void *) GetPayload(), plaintextLength, "Ciphertext Bytes (no tag)");
  hexDump((void *) GetFooter(), tagLength, "Tag (Footer) Bytes");
#endif

  SetIsSecurityProcessed(true);
  return OT_ERROR_NONE;
}

Error RxFrame::AsconDataDecrypt(const KeyMaterial &aMacKey,
                                const ExtAddress &aExtAddress,
                                uint32_t frameCounter,
                                uint8_t securityLevel)
{
  unsigned char key[OT_NETWORK_KEY_SIZE];
  ConvertToAsconKey(aMacKey, key);

  unsigned char assocData[CRYPTO_ABYTES];
  CreateAssocData(assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  CreateAsconNonce(aExtAddress, frameCounter, securityLevel, nonce);

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