/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file includes definitions for generating and processing MLE TLVs.
 */

#ifndef TLVS_HPP_
#define TLVS_HPP_

#include "openthread-core-config.h"

#include <openthread/thread.h>
#include <openthread/platform/toolchain.h>

#include "common/const_cast.hpp"
#include "common/encoding.hpp"
#include "common/error.hpp"
#include "common/offset_range.hpp"
#include "common/type_traits.hpp"

namespace ot {

class Message;

/**
 * Implements TLV generation and parsing.
 */
OT_TOOL_PACKED_BEGIN
class Tlv
{
public:
    /**
     * The maximum length of the Base TLV format.
     */
    static constexpr uint8_t kBaseTlvMaxLength = OT_NETWORK_BASE_TLV_MAX_LENGTH;

    /**
     * Returns the Type value.
     *
     * @returns The Type value.
     */
    uint8_t GetType(void) const { return mType; }

    /**
     * Sets the Type value.
     *
     * @param[in]  aType  The Type value.
     */
    void SetType(uint8_t aType) { mType = aType; }

    /**
     * Indicates whether the TLV is an Extended TLV.
     *
     * @retval TRUE  If the TLV is an Extended TLV.
     * @retval FALSE If the TLV is not an Extended TLV.
     */
    bool IsExtended(void) const { return (mLength == kExtendedLength); }

    /**
     * Returns the Length value.
     *
     * @note This method should be used when TLV is not an Extended TLV, otherwise the returned length from this method
     * would not be correct. When TLV is an Extended TLV, the TLV should be down-casted to the `ExtendedTlv` type and
     * the `ExtendedTlv::GetLength()` should be used instead.
     *
     * @returns The Length value.
     */
    uint8_t GetLength(void) const { return mLength; }

    /**
     * Sets the Length value.
     *
     * @param[in]  aLength  The Length value.
     */
    void SetLength(uint8_t aLength) { mLength = aLength; }

    /**
     * Returns the TLV's total size (number of bytes) including Type, Length, and Value fields.
     *
     * Correctly returns the TLV size independent of whether the TLV is an Extended TLV or not.
     *
     * @returns The total size include Type, Length, and Value fields.
     */
    uint32_t GetSize(void) const;

    /**
     * Returns a pointer to the Value.
     *
     * Can be used independent of whether the TLV is an Extended TLV or not.
     *
     * @returns A pointer to the value.
     */
    uint8_t *GetValue(void);

    /**
     * Returns a pointer to the Value.
     *
     * Can be used independent of whether the TLV is an Extended TLV or not.
     *
     * @returns A pointer to the value.
     */
    const uint8_t *GetValue(void) const;

    /**
     * Returns a pointer to the next TLV.
     *
     * Correctly returns the next TLV independent of whether the current TLV is an Extended TLV or not.
     *
     * @returns A pointer to the next TLV.
     */
    Tlv *GetNext(void) { return reinterpret_cast<Tlv *>(reinterpret_cast<uint8_t *>(this) + GetSize()); }

    /**
     * Returns a pointer to the next TLV.
     *
     * Correctly returns the next TLV independent of whether the current TLV is an Extended TLV or not.
     *
     * @returns A pointer to the next TLV.
     */
    const Tlv *GetNext(void) const
    {
        return reinterpret_cast<const Tlv *>(reinterpret_cast<const uint8_t *>(this) + GetSize());
    }

    /**
     * Appends a TLV to the end of the message.
     *
     * On success, this method grows the message by the size of the TLV.
     *
     * @param[in]  aMessage      A reference to the message to append to.
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    Error AppendTo(Message &aMessage) const;

    /**
     * Reads the value of TLV treating it as a given simple TLV type.
     *
     * This method requires the TLV to be already validated, in particular, its length MUST NOT be less than the
     * required size of the value type. The TLV MUST NOT be extended. If these conditions are not met, the behavior of
     * this method is undefined.
     *
     * @tparam  SimpleTlvType   The simple TLV type to read (must be a sub-class of `SimpleTlvInfo`).
     *
     * @returns The TLV value as `SimpleTlvType::ValueType`.
     */
    template <typename SimpleTlvType> const typename SimpleTlvType::ValueType &ReadValueAs(void) const
    {
        return *reinterpret_cast<const typename SimpleTlvType::ValueType *>(this + 1);
    }

    /**
     * Reads the value of TLV treating it as a given integer-value TLV type.
     *
     * This method requires the TLV to be already validated, in particular, its length MUST NOT be less than the
     * required size of the value type. The TLV MUST NOT be extended. If these conditions are not met, the behavior of
     * this method is undefined.
     *
     * @tparam  UintTlvType     The integer simple TLV type to read (must be a sub-class of `UintTlvInfo`).
     *
     * @returns The TLV value as `UintTlvInfo::UintValueType`.
     */
    template <typename UintTlvType> typename UintTlvType::UintValueType ReadValueAs(void) const
    {
        return BigEndian::Read<typename UintTlvType::UintValueType>(reinterpret_cast<const uint8_t *>(this + 1));
    }

    /**
     * Writes the value of TLV treating it as a given simple TLV type.
     *
     * This method requires the TLV to be already validated, in particular, its length MUST NOT be less than the
     * required size of the value type. The TLV MUST NOT be extended. If these conditions are not met, the behavior of
     * this method is undefined.
     *
     * @tparam  SimpleTlvType   The simple TLV type to read (must be a sub-class of `SimpleTlvInfo`).
     *
     * @param[in] aValue   The new TLV value.
     */
    template <typename SimpleTlvType> void WriteValueAs(const typename SimpleTlvType::ValueType &aValue)
    {
        memcpy(this + 1, &aValue, sizeof(aValue));
    }

    /**
     * Writes the value of TLV treating it as a given integer-value TLV type.
     *
     * This method requires the TLV to be already validated, in particular, its length MUST NOT be less than the
     * required size of the value type. The TLV MUST NOT be extended. If these conditions are not met, the behavior of
     * this method is undefined.
     *
     * @tparam  UintTlvType     The integer simple TLV type to read (must be a sub-class of `UintTlvInfo`).
     *
     * @param[in]  aValue   The new TLV value.
     */
    template <typename UintTlvType> void WriteValueAs(typename UintTlvType::UintValueType aValue)
    {
        return BigEndian::Write<typename UintTlvType::UintValueType>(aValue, reinterpret_cast<uint8_t *>(this + 1));
    }

    //------------------------------------------------------------------------------------------------------------------
    // Static methods for reading/finding/appending TLVs in a `Message`.

    /**
     * Represents information for a parsed TLV from a message.
     */
    struct ParsedInfo
    {
        /**
         * Parses the TLV from a given message at given offset, ensures the TLV is well-formed and its header and
         * value are fully contained in the message.
         *
         * Can be used independent of whether the TLV is an Extended TLV or not.
         *
         * @param[in] aMessage      The message to read from.
         * @param[in] aOffset       The offset in @p aMessage.
         *
         * @retval kErrorNone   Successfully parsed the TLV.
         * @retval kErrorParse  The TLV was not well-formed or not fully contained in @p aMessage.
         */
        Error ParseFrom(const Message &aMessage, uint16_t aOffset);

        /**
         * Parses the TLV from a given message for a given offset range, ensures the TLV is well-formed and its header
         * and value are fully contained in the offset range and the message.
         *
         * Can be used independent of whether the TLV is an Extended TLV or not.
         *
         * @param[in] aMessage      The message to read from.
         * @param[in] aOffsetRange  The offset range in @p aMessage.
         *
         * @retval kErrorNone   Successfully parsed the TLV.
         * @retval kErrorParse  The TLV was not well-formed or not contained in @p aOffsetRange or @p aMessage.
         */
        Error ParseFrom(const Message &aMessage, const OffsetRange &aOffsetRange);

        /**
         * Searches in a given message starting from message offset for a TLV of given type and if found, parses
         * the TLV and validates that the entire TLV is present in the message.
         *
         * Can be used independent of whether the TLV is an Extended TLV or not.
         *
         * @param[in] aMessage  The message to search in.
         * @param[in] aType     The TLV type to search for.
         *
         * @retval kErrorNone      Successfully found and parsed the TLV.
         * @retval kErrorNotFound  Could not find the TLV, or the TLV was not well-formed.
         */
        Error FindIn(const Message &aMessage, uint8_t aType);

        /**
         * Returns the full TLV size in bytes.
         *
         * @returns The TLV size in bytes.
         */
        uint16_t GetSize(void) const { return mTlvOffsetRange.GetLength(); }

        uint8_t     mType;             ///< The TLV type
        bool        mIsExtended;       ///< Whether the TLV is extended or not.
        OffsetRange mTlvOffsetRange;   ///< Offset range containing the full TLV.
        OffsetRange mValueOffsetRange; ///< Offset range containing the TLV's value.
    };

    /**
     * Reads a TLV's value in a message at a given offset expecting a minimum length for the value.
     *
     * Can be used independent of whether the read TLV (from the message) is an Extended TLV or not.
     *
     * @param[in]   aMessage    The message to read from.
     * @param[in]   aOffset     The offset into the message pointing to the start of the TLV.
     * @param[out]  aValue      A buffer to output the TLV's value, must contain (at least) @p aMinLength bytes.
     * @param[in]   aMinLength  The minimum expected length of TLV and number of bytes to copy into @p aValue buffer.
     *
     * @retval kErrorNone        Successfully read the TLV and copied @p aMinLength into @p aValue.
     * @retval kErrorParse       The TLV was not well-formed and could not be parsed.
     */
    static Error ReadTlvValue(const Message &aMessage, uint16_t aOffset, void *aValue, uint8_t aMinLength);

    /**
     * Reads a simple TLV with a single non-integral value in a message at a given offset.
     *
     * @tparam      SimpleTlvType   The simple TLV type to read (must be a sub-class of `SimpleTlvInfo`).
     *
     * @param[in]   aMessage        The message to read from.
     * @param[in]   aOffset         The offset into the message pointing to the start of the TLV.
     * @param[out]  aValue          A reference to the value object to output the read value.
     *
     * @retval kErrorNone        Successfully read the TLV and updated the @p aValue.
     * @retval kErrorParse       The TLV was not well-formed and could not be parsed.
     */
    template <typename SimpleTlvType>
    static Error Read(const Message &aMessage, uint16_t aOffset, typename SimpleTlvType::ValueType &aValue)
    {
        return ReadTlvValue(aMessage, aOffset, &aValue, sizeof(aValue));
    }

    /**
     * Reads a simple TLV with a single integral value in a message at a given offset.
     *
     * @tparam      UintTlvType     The simple TLV type to read (must be a sub-class of `UintTlvInfo`).
     *
     * @param[in]   aMessage        The message to read from.
     * @param[in]   aOffset         The offset into the message pointing to the start of the TLV.
     * @param[out]  aValue          A reference to an unsigned int to output the read value.
     *
     * @retval kErrorNone        Successfully read the TLV and updated the @p aValue.
     * @retval kErrorParse       The TLV was not well-formed and could not be parsed.
     */
    template <typename UintTlvType>
    static Error Read(const Message &aMessage, uint16_t aOffset, typename UintTlvType::UintValueType &aValue)
    {
        return ReadUintTlv(aMessage, aOffset, aValue);
    }

    /**
     * Reads a simple TLV with a UTF-8 string value in a message at a given offset.
     *
     * @tparam      StringTlvType   The simple TLV type to read (must be a sub-class of `StringTlvInfo`).
     *
     * @param[in]   aMessage        The message to read from.
     * @param[in]   aOffset         The offset into the message pointing to the start of the TLV.
     * @param[out]  aValue          A reference to the string buffer to output the read value.
     *
     * @retval kErrorNone        Successfully read the TLV and updated the @p aValue.
     * @retval kErrorParse       The TLV was not well-formed and could not be parsed.
     */
    template <typename StringTlvType>
    static Error Read(const Message &aMessage, uint16_t aOffset, typename StringTlvType::StringType &aValue)
    {
        return ReadStringTlv(aMessage, aOffset, StringTlvType::kMaxStringLength, aValue);
    }

    /**
     * Searches for and reads a requested TLV out of a given message.
     *
     * Can be used independent of whether the read TLV (from message) is an Extended TLV or not.
     *
     * @param[in]   aMessage    A reference to the message.
     * @param[in]   aType       The Type value to search for.
     * @param[in]   aMaxSize    Maximum number of bytes to read.
     * @param[out]  aTlv        A reference to the TLV that will be copied to.
     *
     * @retval kErrorNone       Successfully copied the TLV.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     */
    static Error FindTlv(const Message &aMessage, uint8_t aType, uint16_t aMaxSize, Tlv &aTlv);

    /**
     * Searches for and reads a requested TLV out of a given message.
     *
     * Can be used independent of whether the read TLV (from message) is an Extended TLV or not.
     *
     * @param[in]   aMessage    A reference to the message.
     * @param[in]   aType       The Type value to search for.
     * @param[in]   aMaxSize    Maximum number of bytes to read.
     * @param[out]  aTlv        A reference to the TLV that will be copied to.
     * @param[out]  aOffset     A reference to return the offset to start of the TLV in @p aMessage.
     *
     * @retval kErrorNone       Successfully copied the TLV.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     */
    static Error FindTlv(const Message &aMessage, uint8_t aType, uint16_t aMaxSize, Tlv &aTlv, uint16_t &aOffset);

    /**
     * Searches for and reads a requested TLV out of a given message.
     *
     * Can be used independent of whether the read TLV (from message) is an Extended TLV or not.
     *
     * @tparam      TlvType     The TlvType to search for (must be a sub-class of `Tlv`).
     *
     * @param[in]   aMessage    A reference to the message.
     * @param[out]  aTlv        A reference to the TLV that will be copied to.
     *
     * @retval kErrorNone       Successfully copied the TLV.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     */
    template <typename TlvType> static Error FindTlv(const Message &aMessage, TlvType &aTlv)
    {
        return FindTlv(aMessage, TlvType::kType, sizeof(TlvType), aTlv);
    }

    /**
     * Searches for and reads a requested TLV out of a given message.
     *
     * Can be used independent of whether the read TLV (from message) is an Extended TLV or not.
     *
     * @tparam      TlvType     The TlvType to search for (must be a sub-class of `Tlv`).
     *
     * @param[in]   aMessage    A reference to the message.
     * @param[out]  aTlv        A reference to the TLV that will be copied to.
     * @param[out]  aOffset     A reference to return the offset to start of the TLV in @p aMessage.
     *
     * @retval kErrorNone       Successfully copied the TLV.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     */
    template <typename TlvType> static Error FindTlv(const Message &aMessage, TlvType &aTlv, uint16_t &aOffset)
    {
        return FindTlv(aMessage, TlvType::kType, sizeof(TlvType), aTlv, aOffset);
    }

    /**
     * Finds the offset range of the TLV value for a given TLV type within @p aMessage.
     *
     * Can be used independent of whether the read TLV (from message) is an Extended TLV or not.
     *
     * @param[in]   aMessage      A reference to the message.
     * @param[in]   aType         The Type value to search for.
     * @param[out]  aOffsetRange  A reference to return the offset range of the TLV value when found.
     *
     * @retval kErrorNone       Successfully found the TLV.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     */
    static Error FindTlvValueOffsetRange(const Message &aMessage, uint8_t aType, OffsetRange &aOffsetRange);

    /**
     * Searches for a TLV with a given type in a message, ensures its length is same or larger than
     * an expected minimum value, and then reads its value into a given buffer.
     *
     * If the TLV length is smaller than the minimum length @p aLength, the TLV is considered invalid. In this case,
     * this method returns `kErrorParse` and the @p aValue buffer is not updated.
     *
     * If the TLV length is larger than @p aLength, the TLV is considered valid, but only the first @p aLength bytes
     * of the value are read and copied into the @p aValue buffer.
     *
     * @tparam       TlvType     The TLV type to find.
     *
     * @param[in]    aMessage    A reference to the message.
     * @param[out]   aValue      A buffer to output the value (must contain at least @p aLength bytes).
     * @param[in]    aLength     The expected (minimum) length of the TLV value.
     *
     * @retval kErrorNone       The TLV was found and read successfully. @p aValue is updated.
     * @retval kErrorNotFound   Could not find the TLV with Type @p aType.
     * @retval kErrorParse      TLV was found but it was not well-formed and could not be parsed.
     */
    template <typename TlvType> static Error Find(const Message &aMessage, void *aValue, uint8_t aLength)
    {
        return FindTlv(aMessage, TlvType::kType, aValue, aLength);
    }

    /**
     * Searches for a simple TLV with a single non-integral value in a message, ensures its length is
     * same or larger than the expected `ValueType` object size, and then reads its value into a value object reference.
     *
     * If the TLV length is smaller than the size of @p aValue, the TLV is considered invalid. In this case, this
     * method returns `kErrorParse` and the @p aValue is not updated.
     *
     * If the TLV length is larger than the size of @p aValue, the TLV is considered valid, but the size of
     * `ValueType` bytes are read and copied into the @p aValue.
     *
     * @tparam       SimpleTlvType   The simple TLV type to find (must be a sub-class of `SimpleTlvInfo`)
     *
     * @param[in]    aMessage        A reference to the message.
     * @param[out]   aValue          A reference to the value object to output the read value.
     *
     * @retval kErrorNone         The TLV was found and read successfully. @p aValue is updated.
     * @retval kErrorNotFound     Could not find the TLV with Type @p aType.
     * @retval kErrorParse        TLV was found but it was not well-formed and could not be parsed.
     */
    template <typename SimpleTlvType>
    static Error Find(const Message &aMessage, typename SimpleTlvType::ValueType &aValue)
    {
        return FindTlv(aMessage, SimpleTlvType::kType, &aValue, sizeof(aValue));
    }

    /**
     * Searches for a simple TLV with a single integral value in a message, and then reads its value
     * into a given `uint` reference variable.
     *
     * If the TLV length is smaller than size of integral value, the TLV is considered invalid. In this case, this
     * method returns `kErrorParse` and the @p aValue is not updated.
     *
     * @tparam       UintTlvType     The simple TLV type to find (must be a sub-class of `UintTlvInfo`)
     *
     * @param[in]    aMessage        A reference to the message.
     * @param[out]   aValue          A reference to an unsigned int value to output the TLV's value.
     *
     * @retval kErrorNone         The TLV was found and read successfully. @p aValue is updated.
     * @retval kErrorNotFound     Could not find the TLV with Type @p aType.
     * @retval kErrorParse        TLV was found but it was not well-formed and could not be parsed.
     */
    template <typename UintTlvType>
    static Error Find(const Message &aMessage, typename UintTlvType::UintValueType &aValue)
    {
        return FindUintTlv(aMessage, UintTlvType::kType, aValue);
    }

    /**
     * Searches for a simple TLV with a UTF-8 string value in a message, and then reads its value
     * into a given string buffer.
     *
     * If the TLV length is longer than maximum string length specified by `StringTlvType::kMaxStringLength` then
     * only up to maximum length is read and returned. In this case `kErrorNone` is returned.
     *
     * The returned string in @p aValue is always null terminated.`StringTlvType::StringType` MUST have at least
     * `kMaxStringLength + 1` chars.
     *
     * @tparam       StringTlvType  The simple TLV type to find (must be a sub-class of `StringTlvInfo`)
     *
     * @param[in]    aMessage        A reference to the message.
     * @param[out]   aValue          A reference to a string buffer to output the TLV's value.
     *
     * @retval kErrorNone         The TLV was found and read successfully. @p aValue is updated.
     * @retval kErrorNotFound     Could not find the TLV with Type @p aType.
     * @retval kErrorParse        TLV was found but it was not well-formed and could not be parsed.
     */
    template <typename StringTlvType>
    static Error Find(const Message &aMessage, typename StringTlvType::StringType &aValue)
    {
        return FindStringTlv(aMessage, StringTlvType::kType, StringTlvType::kMaxStringLength, aValue);
    }

    /**
     * Appends a TLV with a given type and value to a message.
     *
     * If the TLV length is longer than maximum base TLV size defined by `kBaseTlvMaxLength` then
     * appends extended TLV.
     *
     * On success this method grows the message by the size of the TLV.
     *
     * @param[in]  aMessage      The message to append to.
     * @param[in]  aType         The TLV type to append.
     * @param[in]  aValue        A buffer containing the TLV value.
     * @param[in]  aLength       The value length (in bytes).
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    static Error AppendTlv(Message &aMessage, uint8_t aType, const void *aValue, uint16_t aLength);

    /**
     * Appends a TLV with a given type and value to a message.
     *
     * On success this method grows the message by the size of the TLV.
     *
     * @tparam     TlvType       The TLV type to append.
     *
     * @param[in]  aMessage      A reference to the message to append to.
     * @param[in]  aValue        A buffer containing the TLV value.
     * @param[in]  aLength       The value length (in bytes).
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    template <typename TlvType> static Error Append(Message &aMessage, const void *aValue, uint8_t aLength)
    {
        return AppendTlv(aMessage, TlvType::kType, aValue, aLength);
    }

    /**
     * Appends a simple TLV with a single (non-integral) value to a message.
     *
     * On success this method grows the message by the size of the TLV.
     *
     * @tparam     SimpleTlvType The simple TLV type to append (must be a sub-class of `SimpleTlvInfo`)
     *
     * @param[in]  aMessage      A reference to the message to append to.
     * @param[in]  aValue        A reference to the object containing TLV's value.
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    template <typename SimpleTlvType>
    static Error Append(Message &aMessage, const typename SimpleTlvType::ValueType &aValue)
    {
        return AppendTlv(aMessage, SimpleTlvType::kType, &aValue, sizeof(aValue));
    }

    /**
     * Appends a simple TLV with a single integral value to a message.
     *
     * On success this method grows the message by the size of the TLV.
     *
     * @tparam     UintTlvType   The simple TLV type to append (must be a sub-class of `UintTlvInfo`)
     *
     * @param[in]  aMessage      A reference to the message to append to.
     * @param[in]  aValue        An unsigned int value to use as TLV's value.
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    template <typename UintTlvType> static Error Append(Message &aMessage, typename UintTlvType::UintValueType aValue)
    {
        return AppendUintTlv(aMessage, UintTlvType::kType, aValue);
    }

    /**
     * Appends a simple TLV with a single UTF-8 string value to a message.
     *
     * On success this method grows the message by the size of the TLV.
     *
     * If the passed in @p aValue string length is longer than the maximum allowed length for the TLV as specified by
     * `StringTlvType::kMaxStringLength`, the first maximum length chars are appended.
     *
     * The @p aValue can be `nullptr` in which case it is treated as an empty string.
     *
     * @tparam     StringTlvType  The simple TLV type to append (must be a sub-class of `StringTlvInfo`)
     *
     * @param[in]  aMessage       A reference to the message to append to.
     * @param[in]  aValue         A pointer to a C string to append as TLV's value.
     *
     * @retval kErrorNone     Successfully appended the TLV to the message.
     * @retval kErrorNoBufs   Insufficient available buffers to grow the message.
     */
    template <typename StringTlvType> static Error Append(Message &aMessage, const char *aValue)
    {
        return AppendStringTlv(aMessage, StringTlvType::kType, StringTlvType::kMaxStringLength, aValue);
    }

    //------------------------------------------------------------------------------------------------------------------
    // Static methods for finding TLVs within a sequence of TLVs.

    /**
     * Searches in a given sequence of TLVs to find the first TLV of a given type.
     *
     * @param[in]  aTlvsStart  A pointer to the start of the sequence of TLVs to search within.
     * @param[in]  aTlvsLength The length (number of bytes) in the TLV sequence.
     * @param[in]  aType       The TLV type to search for.
     *
     * @returns A pointer to the TLV within the TLV sequence if found, or `nullptr` if not found.
     */
    static const Tlv *FindTlv(const void *aTlvsStart, uint16_t aTlvsLength, uint8_t aType);

    /**
     * Searches in a given sequence of TLVs to find the first TLV of a given type.
     *
     * @param[in]  aTlvsStart  A pointer to the start of the sequence of TLVs to search within.
     * @param[in]  aTlvsLength The length (number of bytes) in the TLV sequence.
     * @param[in]  aType       The TLV type to search for.
     *
     * @returns A pointer to the TLV within the TLV sequence if found, or `nullptr` if not found.
     */
    static Tlv *FindTlv(void *aTlvsStart, uint16_t aTlvsLength, uint8_t aType)
    {
        return AsNonConst(FindTlv(AsConst(aTlvsStart), aTlvsLength, aType));
    }

    /**
     * Searches in a given sequence of TLVs to find the first TLV with a give template `TlvType`.
     *
     * @tparam kTlvType        The TLV Type.
     *
     * @param[in]  aTlvsStart  A pointer to the start of the sequence of TLVs to search within.
     * @param[in]  aTlvsLength The length (number of bytes) in TLV sequence.
     *
     * @returns A pointer to the TLV if found, or `nullptr` if not found.
     */
    template <typename TlvType> static TlvType *Find(void *aTlvsStart, uint16_t aTlvsLength)
    {
        return static_cast<TlvType *>(FindTlv(aTlvsStart, aTlvsLength, TlvType::kType));
    }

    /**
     * Searches in a given sequence of TLVs to find the first TLV with a give template `TlvType`.
     *
     * @tparam kTlvType        The TLV Type.
     *
     * @param[in]  aTlvsStart  A pointer to the start of the sequence of TLVs to search within.
     * @param[in]  aTlvsLength The length (number of bytes) in TLV sequence.
     *
     * @returns A pointer to the TLV if found, or `nullptr` if not found.
     */
    template <typename TlvType> static const TlvType *Find(const void *aTlvsStart, uint16_t aTlvsLength)
    {
        return static_cast<const TlvType *>(FindTlv(aTlvsStart, aTlvsLength, TlvType::kType));
    }

protected:
    static const uint8_t kExtendedLength = 255; // Extended Length value.

private:
    static Error FindTlv(const Message &aMessage, uint8_t aType, void *aValue, uint16_t aLength);
    static Error ReadStringTlv(const Message &aMessage, uint16_t aOffset, uint8_t aMaxStringLength, char *aValue);
    static Error FindStringTlv(const Message &aMessage, uint8_t aType, uint8_t aMaxStringLength, char *aValue);
    static Error AppendStringTlv(Message &aMessage, uint8_t aType, uint8_t aMaxStringLength, const char *aValue);
    template <typename UintType> static Error ReadUintTlv(const Message &aMessage, uint16_t aOffset, UintType &aValue);
    template <typename UintType> static Error FindUintTlv(const Message &aMessage, uint8_t aType, UintType &aValue);
    template <typename UintType> static Error AppendUintTlv(Message &aMessage, uint8_t aType, UintType aValue);

    uint8_t mType;
    uint8_t mLength;
} OT_TOOL_PACKED_END;

OT_TOOL_PACKED_BEGIN
class ExtendedTlv : public Tlv
{
public:
    /**
     * Returns the Length value.
     */
    uint16_t GetLength(void) const { return BigEndian::HostSwap16(mLength); }

    /**
     * Sets the Length value.
     *
     * @param[in]  aLength  The Length value.
     */
    void SetLength(uint16_t aLength)
    {
        Tlv::SetLength(kExtendedLength);
        mLength = BigEndian::HostSwap16(aLength);
    }

private:
    uint16_t mLength;
} OT_TOOL_PACKED_END;

/**
 * Casts a `Tlv` pointer to a given subclass `TlvType` pointer.
 *
 * @tparam TlvType  The TLV type to cast into. MUST be a subclass of `Tlv`.
 *
 * @param[in] aTlv   A pointer to a `Tlv` to convert/cast to a `TlvType`.
 *
 * @returns A `TlvType` pointer to `aTlv`.
 */
template <class TlvType> TlvType *As(Tlv *aTlv) { return static_cast<TlvType *>(aTlv); }

/**
 * Casts a `Tlv` pointer to a given subclass `TlvType` pointer.
 *
 * @tparam TlvType  The TLV type to cast into. MUST be a subclass of `Tlv`.
 *
 * @param[in] aTlv   A pointer to a `Tlv` to convert/cast to a `TlvType`.
 *
 * @returns A `TlvType` pointer to `aTlv`.
 */
template <class TlvType> const TlvType *As(const Tlv *aTlv) { return static_cast<const TlvType *>(aTlv); }

/**
 * Casts a `Tlv` reference to a given subclass `TlvType` reference.
 *
 * @tparam TlvType  The TLV type to cast into. MUST be a subclass of `Tlv`.
 *
 * @param[in] aTlv   A reference to a `Tlv` to convert/cast to a `TlvType`.
 *
 * @returns A `TlvType` reference to `aTlv`.
 */
template <class TlvType> TlvType &As(Tlv &aTlv) { return static_cast<TlvType &>(aTlv); }

/**
 * Casts a `Tlv` reference to a given subclass `TlvType` reference.
 *
 * @tparam TlvType  The TLV type to cast into. MUST be a subclass of `Tlv`.
 *
 * @param[in] aTlv   A reference to a `Tlv` to convert/cast to a `TlvType`.
 *
 * @returns A `TlvType` reference to `aTlv`.
 */
template <class TlvType> const TlvType &As(const Tlv &aTlv) { return static_cast<const TlvType &>(aTlv); }

/**
 * Defines constants for a TLV.
 *
 * @tparam kTlvTypeValue   The TLV Type value.
 */
template <uint8_t kTlvTypeValue> class TlvInfo
{
public:
    static constexpr uint8_t kType = kTlvTypeValue; ///< The TLV Type value.
};

/**
 * Defines constants and types for a simple TLV with an unsigned int value type.
 *
 * This class and its sub-classes are intended to be used as the template type in `Tlv::Append<UintTlvType>()`, and
 * the related `Tlv::Find<UintTlvType>()` and `Tlv::Read<UintTlvType>()`.
 *
 * @tparam kTlvTypeValue   The TLV Type value.
 * @tparam UintType        The TLV Value's type (must be an unsigned int, i.e. uint8_t, uint16_t, or uint32_t).
 */
template <uint8_t kTlvTypeValue, typename UintType> class UintTlvInfo : public TlvInfo<kTlvTypeValue>
{
public:
    static_assert(TypeTraits::IsUint<UintType>::kValue, "UintType must be an unsigned int (8, 16, 32, or 64 bit len)");

    typedef UintType UintValueType; ///< The TLV Value unsigned int type.
};

/**
 * Defines constants and types for a simple TLV with a single value.
 *
 * This class and its sub-classes are intended to be used as the template type in `Tlv::Append<SimpleTlvType>()`,
 * and the related `Tlv::Find<SimpleTlvType>()` and `Tlv::Read<SimpleTlvType>()`.
 *
 * @tparam kTlvTypeValue   The TLV Type value.
 * @tparam TlvValueType    The TLV Value's type (must not be an integral type).
 */
template <uint8_t kTlvTypeValue, typename TlvValueType> class SimpleTlvInfo : public TlvInfo<kTlvTypeValue>
{
public:
    static_assert(!TypeTraits::IsPointer<TlvValueType>::kValue, "TlvValueType must not be a pointer");
    static_assert(!TypeTraits::IsUint<TlvValueType>::kValue, "SimpleTlv must not use int value type");
    static_assert(!TypeTraits::IsInt<TlvValueType>::kValue, "SimpleTlv must not use int value type");

    typedef TlvValueType ValueType; ///< The TLV Value type.
};

/**
 * Defines constants and types for a simple TLV with a UTF-8 string value.
 *
 * This class and its sub-classes are intended to be used as the template type in `Tlv::Append<StringTlvType>()`,
 * and the related `Tlv::Find<StringTlvType>()` and `Tlv::Read<StringTlvType>()`.
 *
 * @tparam kTlvTypeValue        The TLV Type value.
 * @tparam kTlvMaxValueLength   The maximum allowed string length (as TLV value).
 */
template <uint8_t kTlvTypeValue, uint8_t kTlvMaxValueLength> class StringTlvInfo : public TlvInfo<kTlvTypeValue>
{
public:
    static constexpr uint8_t kMaxStringLength = kTlvMaxValueLength; ///< Maximum string length.

    typedef char StringType[kMaxStringLength + 1]; ///< String buffer for TLV value.
};

} // namespace ot

#endif // TLVS_HPP_
