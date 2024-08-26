#include "crypto/thread_ascon.hpp"
#include "thread/mle.hpp"
#include "mac/mac_types.hpp"

#include "hexdump.hpp"

#include <inttypes.h>

/**
 * Generates the nonce to be used in ASCON AEAD. The nonce
 * that is created follows the 802.15.4-2006 Specification,
 * page 213.
 *
 * 802.15.4-2006 (pg. 213) state that the nonce is as follows:
 *
 *  | Extended Address | Frame Counter | Security Level |
 *
 * @param[in] sender: the IPv6 address of sender of the MLE packet;
 *                    where the Extended Address will be obtained from
 * @param[in] frameCounter: the frame counter of the MLE packet
 * @param[in] securityLevel: the MLE security level
 *
 * @param[out] aNonce: the pointer to the nonce bytes
*/
void createNonce(ot::Ip6::Address sender,
                 uint32_t frameCounter,
                 uint8_t securityLevel,
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

  memcpy(offset, &securityLevel, sizeof(uint8_t));
  return;
}

/**
 * The Associated Data consists of the sender and receiver 802.15.4
 * extended addresses.
 *
 * I got inspired to use the sender and receiver Extended Addresses
 * as the Associated Data from the discussions in:
 *    https://security.stackexchange.com/a/179279
 *    https://crypto.stackexchange.com/a/84054
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

#define ASCON_TAG_LENGTH kMleSecurityTagSize

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
              Mac::Frame::kSecurityEncMic32, nonce);

#if ASCON_MLE_ENCRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, CRYPTO_ABYTES, "Associated Data Bytes");
#endif

  size_t assocDataLen = CRYPTO_ABYTES;
  uint16_t plaintextLen = aMessage.GetLength() - aCmdOffset;

  // Read plaintext data from the Message.
  uint8_t plaintext[plaintextLen];
  EmptyMemory(plaintext, plaintextLen);
  aMessage.ReadBytes(aCmdOffset, plaintext, plaintextLen);

  uint8_t ciphertext[plaintextLen];
  EmptyMemory(ciphertext, plaintextLen);

  uint8_t tag[ASCON_TAG_LENGTH];
  EmptyMemory(tag, ASCON_TAG_LENGTH);

  libascon_encrypt(ciphertext, tag, key, nonce, assocData,
                   plaintext, assocDataLen, plaintextLen,
                   ASCON_TAG_LENGTH);

  // Replace plaintext with ciphertext.
  aMessage.WriteBytes(aCmdOffset, ciphertext, plaintextLen);

  // Add the ASCON tag at the end of the ciphertext.
  error = aMessage.Append(tag);
  if (error == kErrorNoBufs) {
    otLogCritPlat("Cannot grow message to add tag in MLE packet.");
  }

#if ASCON_MLE_ENCRYPT_HEX_DUMP
  // Length of plaintext and ciphertext (without tag) are the same under ASCON AEAD.
  hexDump((void *) ciphertext, plaintextLen, "Ciphertext Bytes (no tag)");
  hexDump((void *) tag, ASCON_TAG_LENGTH, "MLE Tag Bytes");
#endif

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
              Mac::Frame::kSecurityEncMic32, nonce);

#if ASCON_MLE_DECRYPT_HEX_DUMP
  hexDump((void *) key, OT_NETWORK_KEY_SIZE, "Thread Network Key Bytes");
  hexDump((void *) nonce, ASCON_AEAD_NONCE_LEN, "Nonce Bytes");
  hexDump((void *) assocData, CRYPTO_ABYTES, "Associated Data Bytes");
#endif

  uint16_t cipherLenTotal = aMessage.GetLength() - aCmdOffset;
  uint16_t cipherLenNoTag = cipherLenTotal - ASCON_TAG_LENGTH;
  size_t assocDataLen = CRYPTO_ABYTES;

  // Read the ciphertext payload.
  uint8_t cipherNoTag[cipherLenNoTag];
  EmptyMemory(cipherNoTag, cipherLenNoTag);
  aMessage.ReadBytes(aCmdOffset, cipherNoTag, cipherLenNoTag);

  // Read the tag.
  uint8_t tag[ASCON_TAG_LENGTH];
  EmptyMemory(tag, ASCON_TAG_LENGTH);
  aMessage.ReadBytes(aCmdOffset + cipherLenNoTag, tag, ASCON_TAG_LENGTH);

  unsigned long long plaintextLen = cipherLenNoTag;
  uint8_t plaintext[plaintextLen];
  EmptyMemory(plaintext, plaintextLen);

  bool status = libascon_decrypt(plaintext, key, nonce, assocData,
                                 cipherNoTag, tag, assocDataLen,
                                 cipherLenNoTag, ASCON_TAG_LENGTH);

#if ASCON_MLE_DECRYPT_HEX_DUMP
  hexDump((void *) plaintext, plaintextLen, "Plaintext Bytes (no tag)");
  hexDump((void *) tag, ASCON_TAG_LENGTH, "MLE Tag Bytes");
#endif

  if (status == ASCON_TAG_INVALID) {
    otLogWarnPlat("Invalid ASCON ciphertext (LibAscon - MLE).");
    return OT_ERROR_SECURITY;
  }

  // Replace ciphertext with plaintext.
  aMessage.WriteBytes(aCmdOffset, plaintext, plaintextLen);

  // The tag is not needed in the plaintext payload.
  aMessage.SetLength(aMessage.GetLength() - ASCON_TAG_LENGTH);

  return OT_ERROR_NONE;
}

} // namespace Mle
} // namespace ot