#include "crypto/thread_ascon.hpp"
#include "thread/mle.hpp"
#include "mac/mac_types.hpp"

#include <inttypes.h>

/**
 * The MLE nonce will be composed of the IPv6 address of the sender,
 * the MLE frame counter, and the Key ID mode of the packet.
 *
 * @param[in] sender: the IPv6 address of sender of the MLE packet
 * @param[in] frameCounter: the frame counter of the MLE packet
 * @param[in] keyId: the Key ID mode of the MLE packet
 *
 * @param[out] aNonce: the pointer to the nonce bytes
*/
void createNonce(ot::Ip6::Address sender,
                 uint32_t frameCounter,
                 uint32_t keyId,
                 void* aNonce)
{
  EmptyMemory(aNonce, ASCON_AEAD_NONCE_LEN);

  ot::Mac::ExtAddress senderExt;
  sender.GetIid().ConvertToExtAddress(senderExt);

  uint8_t *offset = (uint8_t *) aNonce;

  memcpy(offset, senderExt.m8, sizeof(ot::Mac::ExtAddress));
  offset += sizeof(ot::Mac::ExtAddress);

  memcpy(offset, &frameCounter, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  memcpy(offset, &keyId, sizeof(uint32_t));
  return;
}

/**
 * The Associated Data consists of the sender and receiver 802.15.4
 * extended addresses.
 *
 * @param[in] sender: the IPv6 address of the sender
 * @param[in] receiver: the IPv6 address of the receiver
 *
 * @param[out] aAssocData: a pointer to the Associated Data bytes in memory
*/
void createAssocData(ot::Ip6::Address sender,
                     ot::Ip6::Address receiver,
                     void* aAssocData)
{
  EmptyMemory(aAssocData, CRYPTO_ABYTES);

  ot::Mac::ExtAddress senderExt, receiverExt;
  sender.GetIid().ConvertToExtAddress(senderExt); // 8 bytes
  receiver.GetIid().ConvertToExtAddress(receiverExt); // 8 bytes

  uint8_t *offset = reinterpret_cast<uint8_t *>(aAssocData);
  memcpy(offset, senderExt.m8, OT_EXT_ADDRESS_SIZE);

  offset += OT_EXT_ADDRESS_SIZE;
  memcpy(offset, receiverExt.m8, OT_EXT_ADDRESS_SIZE);

  return;
}

namespace ot
{
namespace Mle
{

#define ASCON_TAG_LENGTH CRYPTO_ABYTES

Error Mle::AsconMleEncrypt(Message                &aMessage,
                           const Ip6::MessageInfo &aMessageInfo,
                           const SecurityHeader   &aHeader,
                           uint16_t               aCmdOffset)
{
  otError error = OT_ERROR_NONE;

  unsigned char key[OT_NETWORK_KEY_SIZE];
  GetAsconKey(aHeader.GetKeyId(), key);

  unsigned char assocData[CRYPTO_ABYTES];
  createAssocData(aMessageInfo.GetSockAddr(), aMessageInfo.GetPeerAddr(),
                  assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  createNonce(aMessageInfo.GetSockAddr(), aHeader.GetFrameCounter(),
              aHeader.GetKeyId(), nonce);

#if THREAD_ASCON_DEBUG
  AsconDebugPrint(key, nonce, assocData);
#endif // THREAD_ASCON_DEBUG

  uint16_t payloadLen = aMessage.GetLength() - aCmdOffset;

  // Read payload data from the Message.
  uint8_t payload[payloadLen];
  EmptyMemory(payload, payloadLen);
  aMessage.ReadBytes(aCmdOffset, payload, payloadLen);

  unsigned long long expectedCipherLen = payloadLen + ASCON_TAG_LENGTH;
  uint8_t ciphertext[expectedCipherLen];
  EmptyMemory(ciphertext, expectedCipherLen);

  uint8_t *tagPointer = ciphertext + payloadLen;
  ascon_aead128a_encrypt(ciphertext, tagPointer, key, nonce, assocData,
                         payload, CRYPTO_ABYTES, payloadLen,
                         CRYPTO_ABYTES);

  // Replace plaintext with ciphertext.
  aMessage.WriteBytes(aCmdOffset, ciphertext, payloadLen);

  uint8_t tag[ASCON_TAG_LENGTH];
  uint8_t *tagOffset = ciphertext + payloadLen;
  memcpy(&tag, tagOffset, ASCON_TAG_LENGTH);

  // Add the ASCON tag at the end of the ciphertext.
  error = aMessage.Append(tag);
  if (error == kErrorNoBufs) {
    otLogCritPlat("Cannot grow message to add tag in MLE packet.");
  }

  return error;
}

Error Mle::AsconMleDecrypt(Message                &aMessage,
                           const Ip6::MessageInfo &aMessageInfo,
                           const SecurityHeader   &aHeader,
                           uint16_t                aCmdOffset)
{
  unsigned char key[OT_NETWORK_KEY_SIZE];
  GetAsconKey(aHeader.GetKeyId(), key);

  unsigned char assocData[CRYPTO_ABYTES];
  createAssocData(aMessageInfo.GetPeerAddr(), aMessageInfo.GetSockAddr(),
                  assocData);

  unsigned char nonce[ASCON_AEAD_NONCE_LEN];
  createNonce(aMessageInfo.GetPeerAddr(), aHeader.GetFrameCounter(),
              aHeader.GetKeyId(), nonce);

#if THREAD_ASCON_DEBUG
  AsconDebugPrint(key, nonce, assocData);
#endif // THREAD_ASCON_DEBUG

  uint16_t cipherLenTotal = aMessage.GetLength() - aCmdOffset;
  uint16_t cipherLenNoTag = cipherLenTotal - CRYPTO_ABYTES;
  uint16_t tagLen = CRYPTO_ABYTES;

  // Read the ciphertext payload.
  uint8_t cipherNoTag[cipherLenNoTag];
  EmptyMemory(cipherNoTag, cipherLenNoTag);
  aMessage.ReadBytes(aCmdOffset, cipherNoTag, cipherLenNoTag);

  // Read the tag.
  uint8_t tag[tagLen];
  EmptyMemory(tag, tagLen);
  aMessage.ReadBytes(aCmdOffset + cipherLenNoTag, tag, tagLen);

  unsigned long long plaintextLen = cipherLenNoTag;
  uint8_t payload[plaintextLen];
  EmptyMemory(payload, plaintextLen);

  bool status = ascon_aead128a_decrypt(payload, key, nonce, assocData,
                                       cipherNoTag, tag, CRYPTO_ABYTES,
                                       cipherLenNoTag, CRYPTO_ABYTES);

  if (status == ASCON_TAG_INVALID) {
    otLogWarnPlat("Invalid ASCON ciphertext (LibAscon - MLE).");
    return OT_ERROR_SECURITY;
  }

  // Replace ciphertext with plaintext.
  aMessage.WriteBytes(aCmdOffset, payload, plaintextLen);

  // The `CRYPTO_ABYTES` of memory for the tag is not needed for plaintext.
  aMessage.SetLength(aMessage.GetLength() - CRYPTO_ABYTES);

  return OT_ERROR_NONE;
}

} // namespace Mle
} // namespace ot