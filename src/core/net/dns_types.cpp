/*
 *  Copyright (c) 2020, The OpenThread Authors.
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
 *   This file implements generating and processing of DNS headers and helper functions/methods.
 */

#include "dns_types.hpp"

#include "instance/instance.hpp"

namespace ot {
namespace Dns {

Error Header::SetRandomMessageId(void)
{
    return Random::Crypto::FillBuffer(reinterpret_cast<uint8_t *>(&mMessageId), sizeof(mMessageId));
}

Error Header::ResponseCodeToError(Response aResponse)
{
    Error error = kErrorFailed;

    switch (aResponse)
    {
    case kResponseSuccess:
        error = kErrorNone;
        break;

    case kResponseFormatError:   // Server unable to interpret request due to format error.
    case kResponseBadName:       // Bad name.
    case kResponseBadTruncation: // Bad truncation.
    case kResponseNotZone:       // A name is not in the zone.
        error = kErrorParse;
        break;

    case kResponseServerFailure: // Server encountered an internal failure.
        error = kErrorFailed;
        break;

    case kResponseNameError:       // Name that ought to exist, does not exists.
    case kResponseRecordNotExists: // Some RRset that ought to exist, does not exist.
        error = kErrorNotFound;
        break;

    case kResponseNotImplemented: // Server does not support the query type (OpCode).
    case kDsoTypeNotImplemented:  // DSO TLV type is not implemented.
        error = kErrorNotImplemented;
        break;

    case kResponseBadAlg: // Bad algorithm.
        error = kErrorNotCapable;
        break;

    case kResponseNameExists:   // Some name that ought not to exist, does exist.
    case kResponseRecordExists: // Some RRset that ought not to exist, does exist.
        error = kErrorDuplicated;
        break;

    case kResponseRefused: // Server refused to perform operation for policy or security reasons.
    case kResponseNotAuth: // Service is not authoritative for zone.
        error = kErrorSecurity;
        break;

    default:
        break;
    }

    return error;
}

bool Name::Matches(const char *aFirstLabel, const char *aLabels, const char *aDomain) const
{
    bool matches = false;

    VerifyOrExit(!IsEmpty());

    if (IsFromCString())
    {
        const char *namePtr = mString;

        if (aFirstLabel != nullptr)
        {
            matches = CompareAndSkipLabels(namePtr, aFirstLabel, kLabelSeparatorChar);
            VerifyOrExit(matches);
        }

        if (aLabels != nullptr)
        {
            matches = CompareAndSkipLabels(namePtr, aLabels, kLabelSeparatorChar);
            VerifyOrExit(matches);
        }

        matches = CompareAndSkipLabels(namePtr, aDomain, kNullChar);
    }
    else
    {
        uint16_t offset = mOffset;

        if (aFirstLabel != nullptr)
        {
            SuccessOrExit(CompareLabel(*mMessage, offset, aFirstLabel));
        }

        if (aLabels != nullptr)
        {
            SuccessOrExit(CompareMultipleLabels(*mMessage, offset, aLabels));
        }

        SuccessOrExit(CompareName(*mMessage, offset, aDomain));
        matches = true;
    }

exit:
    return matches;
}

bool Name::CompareAndSkipLabels(const char *&aNamePtr, const char *aLabels, char aExpectedNextChar)
{
    // Compares `aNamePtr` to the label string `aLabels` followed by
    // the `aExpectedNextChar`(using case-insensitive match). Upon
    // successful comparison, `aNamePtr` is advanced to point after
    // the matched portion.

    bool     matches = false;
    uint16_t len     = StringLength(aLabels, kMaxNameSize);

    VerifyOrExit(len < kMaxNameSize);

    VerifyOrExit(StringStartsWith(aNamePtr, aLabels, kStringCaseInsensitiveMatch));
    aNamePtr += len;

    VerifyOrExit(*aNamePtr == aExpectedNextChar);
    aNamePtr++;

    matches = true;

exit:
    return matches;
}

Error Name::AppendTo(Message &aMessage) const
{
    Error error;

    if (IsEmpty())
    {
        error = AppendTerminator(aMessage);
    }
    else if (IsFromCString())
    {
        error = AppendName(GetAsCString(), aMessage);
    }
    else
    {
        // Name is from a message. Read labels one by one from
        // `mMessage` and and append each to the `aMessage`.

        LabelIterator iterator(*mMessage, mOffset);

        while (true)
        {
            error = iterator.GetNextLabel();

            switch (error)
            {
            case kErrorNone:
                SuccessOrExit(error = iterator.AppendLabel(aMessage));
                break;

            case kErrorNotFound:
                // We reached the end of name successfully.
                error = AppendTerminator(aMessage);

                OT_FALL_THROUGH;

            default:
                ExitNow();
            }
        }
    }

exit:
    return error;
}

Error Name::AppendLabel(const char *aLabel, Message &aMessage)
{
    return AppendLabel(aLabel, static_cast<uint8_t>(StringLength(aLabel, kMaxLabelSize)), aMessage);
}

Error Name::AppendLabel(const char *aLabel, uint8_t aLength, Message &aMessage)
{
    Error error = kErrorNone;

    VerifyOrExit((0 < aLength) && (aLength <= kMaxLabelLength), error = kErrorInvalidArgs);

    SuccessOrExit(error = aMessage.Append(aLength));
    error = aMessage.AppendBytes(aLabel, aLength);

exit:
    return error;
}

Error Name::AppendMultipleLabels(const char *aLabels, Message &aMessage)
{
    Error    error           = kErrorNone;
    uint16_t index           = 0;
    uint16_t labelStartIndex = 0;
    char     ch;

    VerifyOrExit(aLabels != nullptr);

    do
    {
        ch = aLabels[index];

        if ((ch == kNullChar) || (ch == kLabelSeparatorChar))
        {
            uint8_t labelLength = static_cast<uint8_t>(index - labelStartIndex);

            if (labelLength == 0)
            {
                // Empty label (e.g., consecutive dots) is invalid, but we
                // allow for two cases: (1) where `aLabels` ends with a dot
                // (`labelLength` is zero but we are at end of `aLabels` string
                // and `ch` is null char. (2) if `aLabels` is just "." (we
                // see a dot at index 0, and index 1 is null char).

                error =
                    ((ch == kNullChar) || ((index == 0) && (aLabels[1] == kNullChar))) ? kErrorNone : kErrorInvalidArgs;
                ExitNow();
            }

            VerifyOrExit(index + 1 < kMaxEncodedLength, error = kErrorInvalidArgs);
            SuccessOrExit(error = AppendLabel(&aLabels[labelStartIndex], labelLength, aMessage));

            labelStartIndex = index + 1;
        }

        index++;

    } while (ch != kNullChar);

exit:
    return error;
}

Error Name::AppendTerminator(Message &aMessage)
{
    uint8_t terminator = 0;

    return aMessage.Append(terminator);
}

Error Name::AppendPointerLabel(uint16_t aOffset, Message &aMessage)
{
    Error    error;
    uint16_t value;

#if OPENTHREAD_CONFIG_REFERENCE_DEVICE_ENABLE
    if (!Instance::IsDnsNameCompressionEnabled())
    {
        // If "DNS name compression" mode is disabled, instead of
        // appending the pointer label, read the name from the message
        // and append it uncompressed. Note that the `aOffset` parameter
        // in this method is given relative to the start of DNS header
        // in `aMessage` (which `aMessage.GetOffset()` specifies).

        error = Name(aMessage, aOffset + aMessage.GetOffset()).AppendTo(aMessage);
        ExitNow();
    }
#endif

    // A pointer label takes the form of a two byte sequence as a
    // `uint16_t` value. The first two bits are ones. This allows a
    // pointer to be distinguished from a text label, since the text
    // label must begin with two zero bits (note that labels are
    // restricted to 63 octets or less). The next 14-bits specify
    // an offset value relative to start of DNS header.

    OT_ASSERT(aOffset < kPointerLabelTypeUint16);

    value = BigEndian::HostSwap16(aOffset | kPointerLabelTypeUint16);

    ExitNow(error = aMessage.Append(value));

exit:
    return error;
}

Error Name::AppendName(const char *aName, Message &aMessage)
{
    Error error;

    SuccessOrExit(error = AppendMultipleLabels(aName, aMessage));
    error = AppendTerminator(aMessage);

exit:
    return error;
}

Error Name::ParseName(const Message &aMessage, uint16_t &aOffset)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);

    while (true)
    {
        error = iterator.GetNextLabel();

        switch (error)
        {
        case kErrorNone:
            break;

        case kErrorNotFound:
            // We reached the end of name successfully.
            aOffset = iterator.mNameEndOffset;
            error   = kErrorNone;

            OT_FALL_THROUGH;

        default:
            ExitNow();
        }
    }

exit:
    return error;
}

Error Name::ReadLabel(const Message &aMessage, uint16_t &aOffset, char *aLabelBuffer, uint8_t &aLabelLength)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);

    SuccessOrExit(error = iterator.GetNextLabel());
    SuccessOrExit(error = iterator.ReadLabel(aLabelBuffer, aLabelLength, /* aAllowDotCharInLabel */ true));
    aOffset = iterator.mNextLabelOffset;

exit:
    return error;
}

Error Name::ReadName(const Message &aMessage, uint16_t &aOffset, char *aNameBuffer, uint16_t aNameBufferSize)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);
    bool          firstLabel = true;
    uint8_t       labelLength;

    while (true)
    {
        error = iterator.GetNextLabel();

        switch (error)
        {
        case kErrorNone:

            if (!firstLabel)
            {
                *aNameBuffer++ = kLabelSeparatorChar;
                aNameBufferSize--;

                // No need to check if we have reached end of the name buffer
                // here since `iterator.ReadLabel()` would verify it.
            }

            labelLength = static_cast<uint8_t>(Min(static_cast<uint16_t>(kMaxLabelSize), aNameBufferSize));
            SuccessOrExit(error = iterator.ReadLabel(aNameBuffer, labelLength, /* aAllowDotCharInLabel */ firstLabel));
            aNameBuffer += labelLength;
            aNameBufferSize -= labelLength;
            firstLabel = false;
            break;

        case kErrorNotFound:
            // We reach the end of name successfully. Always add a terminating dot
            // at the end.
            *aNameBuffer++ = kLabelSeparatorChar;
            aNameBufferSize--;
            VerifyOrExit(aNameBufferSize >= sizeof(uint8_t), error = kErrorNoBufs);
            *aNameBuffer = kNullChar;
            aOffset      = iterator.mNameEndOffset;
            error        = kErrorNone;

            OT_FALL_THROUGH;

        default:
            ExitNow();
        }
    }

exit:
    return error;
}

Error Name::CompareLabel(const Message &aMessage, uint16_t &aOffset, const char *aLabel)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);

    SuccessOrExit(error = iterator.GetNextLabel());
    VerifyOrExit(iterator.CompareLabel(aLabel, kIsSingleLabel), error = kErrorNotFound);
    aOffset = iterator.mNextLabelOffset;

exit:
    return error;
}

Error Name::CompareMultipleLabels(const Message &aMessage, uint16_t &aOffset, const char *aLabels)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);

    while (true)
    {
        SuccessOrExit(error = iterator.GetNextLabel());
        VerifyOrExit(iterator.CompareLabel(aLabels, !kIsSingleLabel), error = kErrorNotFound);

        if (*aLabels == kNullChar)
        {
            aOffset = iterator.mNextLabelOffset;
            ExitNow();
        }
    }

exit:
    return error;
}

Error Name::CompareName(const Message &aMessage, uint16_t &aOffset, const char *aName)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);
    bool          matches = true;

    if (*aName == kLabelSeparatorChar)
    {
        aName++;
        VerifyOrExit(*aName == kNullChar, error = kErrorInvalidArgs);
    }

    while (true)
    {
        error = iterator.GetNextLabel();

        switch (error)
        {
        case kErrorNone:
            if (matches && !iterator.CompareLabel(aName, !kIsSingleLabel))
            {
                matches = false;
            }

            break;

        case kErrorNotFound:
            // We reached the end of the name in `aMessage`. We check if
            // all the previous labels matched so far, and we are also
            // at the end of `aName` string (see null char), then we
            // return `kErrorNone` indicating a successful comparison
            // (full match). Otherwise we return `kErrorNotFound` to
            // indicate failed comparison.

            if (matches && (*aName == kNullChar))
            {
                error = kErrorNone;
            }

            aOffset = iterator.mNameEndOffset;

            OT_FALL_THROUGH;

        default:
            ExitNow();
        }
    }

exit:
    return error;
}

Error Name::CompareName(const Message &aMessage, uint16_t &aOffset, const Message &aMessage2, uint16_t aOffset2)
{
    Error         error;
    LabelIterator iterator(aMessage, aOffset);
    LabelIterator iterator2(aMessage2, aOffset2);
    bool          matches = true;

    while (true)
    {
        error = iterator.GetNextLabel();

        switch (error)
        {
        case kErrorNone:
            // If all the previous labels matched so far, then verify
            // that we can get the next label on `iterator2` and that it
            // matches the label from `iterator`.
            if (matches && (iterator2.GetNextLabel() != kErrorNone || !iterator.CompareLabel(iterator2)))
            {
                matches = false;
            }

            break;

        case kErrorNotFound:
            // We reached the end of the name in `aMessage`. We check
            // that `iterator2` is also at its end, and if all previous
            // labels matched we return `kErrorNone`.

            if (matches && (iterator2.GetNextLabel() == kErrorNotFound))
            {
                error = kErrorNone;
            }

            aOffset = iterator.mNameEndOffset;

            OT_FALL_THROUGH;

        default:
            ExitNow();
        }
    }

exit:
    return error;
}

Error Name::CompareName(const Message &aMessage, uint16_t &aOffset, const Name &aName)
{
    return aName.IsFromCString()
               ? CompareName(aMessage, aOffset, aName.mString)
               : (aName.IsFromMessage() ? CompareName(aMessage, aOffset, *aName.mMessage, aName.mOffset)
                                        : ParseName(aMessage, aOffset));
}

Error Name::LabelIterator::GetNextLabel(void)
{
    Error error;

    while (true)
    {
        uint8_t labelLength;
        uint8_t labelType;

        SuccessOrExit(error = mMessage.Read(mNextLabelOffset, labelLength));

        labelType = labelLength & kLabelTypeMask;

        if (labelType == kTextLabelType)
        {
            if (labelLength == 0)
            {
                // Zero label length indicates end of a name.

                if (!IsEndOffsetSet())
                {
                    mNameEndOffset = mNextLabelOffset + sizeof(uint8_t);
                }

                ExitNow(error = kErrorNotFound);
            }

            mLabelStartOffset = mNextLabelOffset + sizeof(uint8_t);
            mLabelLength      = labelLength;
            mNextLabelOffset  = mLabelStartOffset + labelLength;
            ExitNow();
        }
        else if (labelType == kPointerLabelType)
        {
            // A pointer label takes the form of a two byte sequence as a
            // `uint16_t` value. The first two bits are ones. The next 14 bits
            // specify an offset value from the start of the DNS header.

            uint16_t pointerValue;
            uint16_t nextLabelOffset;

            SuccessOrExit(error = mMessage.Read(mNextLabelOffset, pointerValue));

            if (!IsEndOffsetSet())
            {
                mNameEndOffset = mNextLabelOffset + sizeof(uint16_t);
            }

            // `mMessage.GetOffset()` must point to the start of the
            // DNS header.
            nextLabelOffset = mMessage.GetOffset() + (BigEndian::HostSwap16(pointerValue) & kPointerLabelOffsetMask);
            VerifyOrExit(nextLabelOffset < mMinLabelOffset, error = kErrorParse);
            mNextLabelOffset = nextLabelOffset;
            mMinLabelOffset  = nextLabelOffset;

            // Go back through the `while(true)` loop to get the next label.
        }
        else
        {
            ExitNow(error = kErrorParse);
        }
    }

exit:
    return error;
}

Error Name::LabelIterator::ReadLabel(char *aLabelBuffer, uint8_t &aLabelLength, bool aAllowDotCharInLabel) const
{
    Error error;

    VerifyOrExit(mLabelLength < aLabelLength, error = kErrorNoBufs);

    SuccessOrExit(error = mMessage.Read(mLabelStartOffset, aLabelBuffer, mLabelLength));
    aLabelBuffer[mLabelLength] = kNullChar;
    aLabelLength               = mLabelLength;

    if (!aAllowDotCharInLabel)
    {
        VerifyOrExit(StringFind(aLabelBuffer, kLabelSeparatorChar) == nullptr, error = kErrorParse);
    }

exit:
    return error;
}

bool Name::LabelIterator::CaseInsensitiveMatch(uint8_t aFirst, uint8_t aSecond)
{
    return ToLowercase(static_cast<char>(aFirst)) == ToLowercase(static_cast<char>(aSecond));
}

bool Name::LabelIterator::CompareLabel(const char *&aName, bool aIsSingleLabel) const
{
    // This method compares the current label in the iterator with the
    // `aName` string. `aIsSingleLabel` indicates whether `aName` is a
    // single label, or a sequence of labels separated by dot '.' char.
    // If the label matches `aName`, then `aName` pointer is moved
    // forward to the start of the next label (skipping over the `.`
    // char). This method returns `true` when the labels match, `false`
    // otherwise.

    bool matches = false;

    VerifyOrExit(StringLength(aName, mLabelLength) == mLabelLength);
    matches = mMessage.CompareBytes(mLabelStartOffset, aName, mLabelLength, CaseInsensitiveMatch);

    VerifyOrExit(matches);

    aName += mLabelLength;

    // If `aName` is a single label, we should be also at the end of the
    // `aName` string. Otherwise, we should see either null or dot '.'
    // character (in case `aName` contains multiple labels).

    matches = (*aName == kNullChar);

    if (!aIsSingleLabel && (*aName == kLabelSeparatorChar))
    {
        matches = true;
        aName++;
    }

exit:
    return matches;
}

bool Name::LabelIterator::CompareLabel(const LabelIterator &aOtherIterator) const
{
    // This method compares the current label in the iterator with the
    // label from another iterator.

    return (mLabelLength == aOtherIterator.mLabelLength) &&
           mMessage.CompareBytes(mLabelStartOffset, aOtherIterator.mMessage, aOtherIterator.mLabelStartOffset,
                                 mLabelLength, CaseInsensitiveMatch);
}

Error Name::LabelIterator::AppendLabel(Message &aMessage) const
{
    // This method reads and appends the current label in the iterator
    // to `aMessage`.

    Error error;

    VerifyOrExit((0 < mLabelLength) && (mLabelLength <= kMaxLabelLength), error = kErrorInvalidArgs);
    SuccessOrExit(error = aMessage.Append(mLabelLength));
    error = aMessage.AppendBytesFromMessage(mMessage, mLabelStartOffset, mLabelLength);

exit:
    return error;
}

Error Name::ExtractLabels(const char *aName, const char *aSuffixName, char *aLabels, uint16_t aLabelsSize)
{
    Error       error        = kErrorParse;
    uint16_t    nameLength   = StringLength(aName, kMaxNameSize);
    uint16_t    suffixLength = StringLength(aSuffixName, kMaxNameSize);
    const char *suffixStart;

    VerifyOrExit(nameLength < kMaxNameSize);
    VerifyOrExit(suffixLength < kMaxNameSize);

    VerifyOrExit(nameLength > suffixLength);

    suffixStart = aName + nameLength - suffixLength;
    VerifyOrExit(StringMatch(suffixStart, aSuffixName, kStringCaseInsensitiveMatch));
    suffixStart--;
    VerifyOrExit(*suffixStart == kLabelSeparatorChar);

    // Determine the labels length to copy
    nameLength -= (suffixLength + 1);
    VerifyOrExit(nameLength < aLabelsSize, error = kErrorNoBufs);

    if (aLabels != aName)
    {
        memmove(aLabels, aName, nameLength);
    }

    aLabels[nameLength] = kNullChar;
    error               = kErrorNone;

exit:
    return error;
}

bool Name::IsSubDomainOf(const char *aName, const char *aDomain)
{
    bool     match             = false;
    bool     nameEndsWithDot   = false;
    bool     domainEndsWithDot = false;
    uint16_t nameLength        = StringLength(aName, kMaxNameLength);
    uint16_t domainLength      = StringLength(aDomain, kMaxNameLength);

    if (nameLength > 0 && aName[nameLength - 1] == kLabelSeparatorChar)
    {
        nameEndsWithDot = true;
        --nameLength;
    }

    if (domainLength > 0 && aDomain[domainLength - 1] == kLabelSeparatorChar)
    {
        domainEndsWithDot = true;
        --domainLength;
    }

    VerifyOrExit(nameLength >= domainLength);

    aName += nameLength - domainLength;

    if (nameLength > domainLength)
    {
        VerifyOrExit(aName[-1] == kLabelSeparatorChar);
    }

    // This method allows either `aName` or `aDomain` to include or
    // exclude the last `.` character. If both include it or if both
    // do not, we do a full comparison using `StringMatch()`.
    // Otherwise (i.e., when one includes and the other one does not)
    // we use `StringStartWith()` to allow the extra `.` character.

    if (nameEndsWithDot == domainEndsWithDot)
    {
        match = StringMatch(aName, aDomain, kStringCaseInsensitiveMatch);
    }
    else if (nameEndsWithDot)
    {
        // `aName` ends with dot, but `aDomain` does not.
        match = StringStartsWith(aName, aDomain, kStringCaseInsensitiveMatch);
    }
    else
    {
        // `aDomain` ends with dot, but `aName` does not.
        match = StringStartsWith(aDomain, aName, kStringCaseInsensitiveMatch);
    }

exit:
    return match;
}

bool Name::IsSameDomain(const char *aDomain1, const char *aDomain2)
{
    return IsSubDomainOf(aDomain1, aDomain2) && IsSubDomainOf(aDomain2, aDomain1);
}

void ResourceRecord::UpdateRecordLengthInMessage(Message &aMessage, uint16_t aOffset)
{
    ResourceRecord record;

    IgnoreError(aMessage.Read(aOffset, record));
    record.SetLength(aMessage.GetLength() - aOffset - sizeof(ResourceRecord));
    aMessage.Write(aOffset, record);
}

Error ResourceRecord::ParseRecords(const Message &aMessage, uint16_t &aOffset, uint16_t aNumRecords)
{
    Error error = kErrorNone;

    while (aNumRecords > 0)
    {
        ResourceRecord record;

        SuccessOrExit(error = Name::ParseName(aMessage, aOffset));
        SuccessOrExit(error = record.ReadFrom(aMessage, aOffset));
        aOffset += static_cast<uint16_t>(record.GetSize());
        aNumRecords--;
    }

exit:
    return error;
}

Error ResourceRecord::FindRecord(const Message &aMessage, uint16_t &aOffset, uint16_t &aNumRecords, const Name &aName)
{
    Error error;

    while (aNumRecords > 0)
    {
        bool           matches = true;
        ResourceRecord record;

        error = Name::CompareName(aMessage, aOffset, aName);

        switch (error)
        {
        case kErrorNone:
            break;
        case kErrorNotFound:
            matches = false;
            break;
        default:
            ExitNow();
        }

        SuccessOrExit(error = record.ReadFrom(aMessage, aOffset));
        aNumRecords--;
        VerifyOrExit(!matches);
        aOffset += static_cast<uint16_t>(record.GetSize());
    }

    error = kErrorNotFound;

exit:
    return error;
}

Error ResourceRecord::FindRecord(const Message  &aMessage,
                                 uint16_t       &aOffset,
                                 uint16_t        aNumRecords,
                                 uint16_t        aIndex,
                                 const Name     &aName,
                                 uint16_t        aType,
                                 ResourceRecord &aRecord,
                                 uint16_t        aMinRecordSize)
{
    // This static method searches in `aMessage` starting from `aOffset`
    // up to maximum of `aNumRecords`, for the `(aIndex+1)`th
    // occurrence of a resource record of type `aType` with record name
    // matching `aName`. It also verifies that the record size is larger
    // than `aMinRecordSize`. If found, `aMinRecordSize` bytes from the
    // record are read and copied into `aRecord`. In this case `aOffset`
    // is updated to point to the last record byte read from the message
    // (so that the caller can read any remaining fields in the record
    // data).

    Error    error;
    uint16_t offset = aOffset;
    uint16_t recordOffset;

    while (aNumRecords > 0)
    {
        SuccessOrExit(error = FindRecord(aMessage, offset, aNumRecords, aName));

        // Save the offset to start of `ResourceRecord` fields.
        recordOffset = offset;

        error = ReadRecord(aMessage, offset, aType, aRecord, aMinRecordSize);

        if (error == kErrorNotFound)
        {
            // `ReadRecord()` already updates the `offset` to skip
            // over a non-matching record.
            continue;
        }

        SuccessOrExit(error);

        if (aIndex == 0)
        {
            aOffset = offset;
            ExitNow();
        }

        aIndex--;

        // Skip over the record.
        offset = static_cast<uint16_t>(recordOffset + aRecord.GetSize());
    }

    error = kErrorNotFound;

exit:
    return error;
}

Error ResourceRecord::ReadRecord(const Message  &aMessage,
                                 uint16_t       &aOffset,
                                 uint16_t        aType,
                                 ResourceRecord &aRecord,
                                 uint16_t        aMinRecordSize)
{
    // This static method tries to read a matching resource record of a
    // given type and a minimum record size from a message. The `aType`
    // value of `kTypeAny` matches any type.  If the record in the
    // message does not match, it skips over the record. Please see
    // `ReadRecord<RecordType>()` for more details.

    Error          error;
    ResourceRecord record;

    SuccessOrExit(error = record.ReadFrom(aMessage, aOffset));

    if (((aType == kTypeAny) || (record.GetType() == aType)) && (record.GetSize() >= aMinRecordSize))
    {
        IgnoreError(aMessage.Read(aOffset, &aRecord, aMinRecordSize));
        aOffset += aMinRecordSize;
    }
    else
    {
        // Skip over the entire record.
        aOffset += static_cast<uint16_t>(record.GetSize());
        error = kErrorNotFound;
    }

exit:
    return error;
}

Error ResourceRecord::ReadName(const Message &aMessage,
                               uint16_t      &aOffset,
                               uint16_t       aStartOffset,
                               char          *aNameBuffer,
                               uint16_t       aNameBufferSize,
                               bool           aSkipRecord) const
{
    // This protected method parses and reads a name field in a record
    // from a message. It is intended only for sub-classes of
    // `ResourceRecord`.
    //
    // On input `aOffset` gives the offset in `aMessage` to the start of
    // name field. `aStartOffset` gives the offset to the start of the
    // `ResourceRecord`. `aSkipRecord` indicates whether to skip over
    // the entire resource record or just the read name. On exit, when
    // successfully read, `aOffset` is updated to either point after the
    // end of record or after the the name field.
    //
    // When read successfully, this method returns `kErrorNone`. On a
    // parse error (invalid format) returns `kErrorParse`. If the
    // name does not fit in the given name buffer it returns
    // `kErrorNoBufs`

    Error error = kErrorNone;

    SuccessOrExit(error = Name::ReadName(aMessage, aOffset, aNameBuffer, aNameBufferSize));
    VerifyOrExit(aOffset <= aStartOffset + GetSize(), error = kErrorParse);

    VerifyOrExit(aSkipRecord);
    aOffset = aStartOffset;
    error   = SkipRecord(aMessage, aOffset);

exit:
    return error;
}

Error ResourceRecord::SkipRecord(const Message &aMessage, uint16_t &aOffset) const
{
    // This protected method parses and skips over a resource record
    // in a message.
    //
    // On input `aOffset` gives the offset in `aMessage` to the start of
    // the `ResourceRecord`. On exit, when successfully parsed, `aOffset`
    // is updated to point to byte after the entire record.

    Error error;

    SuccessOrExit(error = CheckRecord(aMessage, aOffset));
    aOffset += static_cast<uint16_t>(GetSize());

exit:
    return error;
}

Error ResourceRecord::CheckRecord(const Message &aMessage, uint16_t aOffset) const
{
    // This method checks that the entire record (including record data)
    // is present in `aMessage` at `aOffset` (pointing to the start of
    // the `ResourceRecord` in `aMessage`).

    return (aOffset + GetSize() <= aMessage.GetLength()) ? kErrorNone : kErrorParse;
}

Error ResourceRecord::ReadFrom(const Message &aMessage, uint16_t aOffset)
{
    // This method reads the `ResourceRecord` from `aMessage` at
    // `aOffset`. It verifies that the entire record (including record
    // data) is present in the message.

    Error error;

    SuccessOrExit(error = aMessage.Read(aOffset, *this));
    error = CheckRecord(aMessage, aOffset);

exit:
    return error;
}

const ResourceRecord::DataRecipe *ResourceRecord::FindDataRecipeFor(uint16_t aRecordType)
{
    static constexpr DataRecipe kRecipes[] = {
        {kTypeNs, 0, 1, 0},
        {kTypeCname, 0, 1, 0},
        {kTypeSoa, 0, 2, 5 * sizeof(uint32_t)}, // mname, rname, followed by five 32-bit values.
        {kTypePtr, 0, 1, 0},
        {kTypeMx, sizeof(uint16_t), 1, 0},    // `preference` 16-bit field, exchange name [RFC 1035]
        {kTypeRp, 0, 2, 0},                   /// `mbox-dname` `txt-dname` [RFC 1183]
        {kTypeAfsdb, sizeof(uint16_t), 1, 0}, // `sub-type` 16-bit field, host name [RFC 1183]
        {kTypeRt, sizeof(uint16_t), 1, 0},    // `preference` 16-bit field, host name [RFC 1183]
        {kTypePx, sizeof(uint16_t), 2, 0},    // `preference` 16-bit field, two names [RFC 2163]
        {kTypeSrv, sizeof(SrvRecord) - sizeof(ResourceRecord), 1, 0},
        {kTypeKx, sizeof(uint16_t), 1, 0}, // `preference` 16-bit field, name [RFC 2230]
        {kTypeDname, 0, 1, 0},
        {kTypeNsec, 0, 1, NsecRecord::TypeBitMap::kMinSize},
    };

    static_assert(BinarySearch::IsSorted(kRecipes), "kRecipes is not sorted");

    return BinarySearch::Find(aRecordType, kRecipes);
}

Error ResourceRecord::DecompressRecordData(const Message &aMessage, uint16_t aOffset, OwnedPtr<Message> &aDataMsg)
{
    // Reads the `ResourceRecord` header to identify the record type
    // and uses a predefined recipe to parse the record data.

    Error             error;
    ResourceRecord    record;
    const DataRecipe *recipe;
    uint16_t          startOffset;
    uint16_t          remainingLength;

    SuccessOrExit(error = record.ReadFrom(aMessage, aOffset));
    aOffset += sizeof(ResourceRecord);

    recipe = FindDataRecipeFor(record.GetType());

    if (recipe == nullptr)
    {
        aDataMsg.Free();
        error = kErrorNone;
        ExitNow();
    }

    aDataMsg.Reset(aMessage.Get<MessagePool>().Allocate(Message::kTypeOther));
    VerifyOrExit(!aDataMsg.IsNull(), error = kErrorNoBufs);

    startOffset = aOffset;

    // Check and copy the prefix bytes in the record data.

    VerifyOrExit(record.GetLength() >= recipe->mNumPrefixBytes, error = kErrorParse);
    SuccessOrExit(error = aDataMsg->AppendBytesFromMessage(aMessage, aOffset, recipe->mNumPrefixBytes));
    aOffset += recipe->mNumPrefixBytes;

    // Read and decompress embedded DNS names in the record data.

    for (uint8_t numNames = 0; numNames < recipe->mNumNames; numNames++)
    {
        Name name(aMessage, aOffset);

        // ParseName() updates `aOffset` to point to the byte after
        // the end of name field.

        SuccessOrExit(error = Name::ParseName(aMessage, aOffset));
        SuccessOrExit(error = name.AppendTo(*aDataMsg));
    }

    // Determine the remaining length after the names in the record
    // data. Ensure we have at least `mMinNumSuffixBytes` and copy
    // them into `aDataMsg`.

    VerifyOrExit(aOffset - startOffset <= record.GetLength(), error = kErrorParse);
    remainingLength = record.GetLength() - (aOffset - startOffset);

    VerifyOrExit(remainingLength >= recipe->mMinNumSuffixBytes, error = kErrorParse);

    SuccessOrExit(error = aDataMsg->AppendBytesFromMessage(aMessage, aOffset, remainingLength));

exit:
    return error;
}

Error ResourceRecord::AppendTranslatedRecordDataTo(Message                       &aMessage,
                                                   uint16_t                       aRecordType,
                                                   const Data<kWithUint16Length> &aData,
                                                   const char                    *aOriginalDomain,
                                                   uint16_t                       aTranslatedDomainOffset)
{
    Error             error  = kErrorNone;
    const DataRecipe *recipe = FindDataRecipeFor(aRecordType);
    OwnedPtr<Message> dataMsg;
    uint16_t          offset;
    uint16_t          remainingLength;

    if (recipe == nullptr)
    {
        error = aMessage.AppendData(aData);
        ExitNow();
    }

    dataMsg.Reset(aMessage.Get<MessagePool>().Allocate(Message::kTypeOther));
    VerifyOrExit(dataMsg != nullptr, error = kErrorNoBufs);
    SuccessOrExit(error = dataMsg->AppendData(aData));

    // Append the prefix bytes in the record data.

    offset = 0;
    SuccessOrExit(error = aMessage.AppendBytesFromMessage(*dataMsg, offset, recipe->mNumPrefixBytes));
    offset += recipe->mNumPrefixBytes;

    // Translate and append the embedded DNS names

    for (uint8_t numNames = 0; numNames < recipe->mNumNames; numNames++)
    {
        Name::LabelBuffer label;
        uint8_t           labelLength;
        uint16_t          labelOffset;

        // Read labels one by one and append them to `aMessage`.
        // First, check if the remaining labels match the original
        // domain name and if so, append the translated domain name
        // (as a compressed pointer label) instead.

        labelOffset = offset;

        while (true)
        {
            uint16_t compareOffset = labelOffset;

            if (Name::CompareName(*dataMsg, compareOffset, aOriginalDomain) == kErrorNone)
            {
                SuccessOrExit(error = Name::AppendPointerLabel(aTranslatedDomainOffset, aMessage));
                break;
            }

            labelLength = sizeof(label);
            error       = Name::ReadLabel(*dataMsg, labelOffset, label, labelLength);

            if (error == kErrorNotFound)
            {
                // Reached end of the label
                break;
            }

            SuccessOrExit(error);

            SuccessOrExit(error = Name::AppendLabel(label, aMessage));
        }

        // Parse name and update `offset` to the end of name field.
        SuccessOrExit(error = Name::ParseName(*dataMsg, offset));
    }

    // Append the extra bytes after the name(s).

    VerifyOrExit(offset <= dataMsg->GetLength(), error = kErrorParse);
    remainingLength = dataMsg->GetLength() - offset;

    VerifyOrExit(remainingLength >= recipe->mMinNumSuffixBytes, error = kErrorParse);
    SuccessOrExit(error = aMessage.AppendBytesFromMessage(*dataMsg, offset, remainingLength));

exit:
    return error;
}

ResourceRecord::TypeInfoString ResourceRecord::TypeToString(uint16_t aRecordType)
{
    static constexpr Stringify::Entry kRecordTypeTable[] = {
        {kTypeA, "A"},     {kTypeNs, "NS"},       {kTypeCname, "CNAME"}, {kTypeSoa, "SOA"},     {kTypePtr, "PTR"},
        {kTypeMx, "MX"},   {kTypeTxt, "TXT"},     {kTypeRp, "RP"},       {kTypeAfsdb, "AFSDB"}, {kTypeRt, "RT"},
        {kTypeSig, "SIG"}, {kTypeKey, "KEY"},     {kTypePx, "PX"},       {kTypeAaaa, "AAAA"},   {kTypeSrv, "SRV"},
        {kTypeKx, "KX"},   {kTypeDname, "DNAME"}, {kTypeOpt, "OPT"},     {kTypeNsec, "NSEC"},   {kTypeAny, "ANY"},
    };

    static_assert(Stringify::IsSorted(kRecordTypeTable), "kRecordTypeTable is not sorted");

    TypeInfoString string;
    const char    *lookupResult = Stringify::Lookup(aRecordType, kRecordTypeTable, nullptr);

    if (lookupResult != nullptr)
    {
        string.Append("%s", lookupResult);
    }
    else
    {
        string.Append("RR:%u", aRecordType);
    }

    return string;
}

void TxtEntry::Iterator::Init(const uint8_t *aTxtData, uint16_t aTxtDataLength)
{
    SetTxtData(aTxtData);
    SetTxtDataLength(aTxtDataLength);
    SetTxtDataPosition(0);
}

Error TxtEntry::Iterator::GetNextEntry(TxtEntry &aEntry)
{
    Error       error = kErrorNone;
    uint8_t     length;
    uint8_t     index;
    const char *cur;
    char       *keyBuffer = GetKeyBuffer();

    static_assert(sizeof(mChar) >= TxtEntry::kMaxKeyLength + 1, "KeyBuffer cannot fit the max key length");

    VerifyOrExit(GetTxtData() != nullptr, error = kErrorParse);

    aEntry.mKey = keyBuffer;

    while ((cur = GetTxtData() + GetTxtDataPosition()) < GetTxtDataEnd())
    {
        length = static_cast<uint8_t>(*cur);

        cur++;
        VerifyOrExit(cur + length <= GetTxtDataEnd(), error = kErrorParse);
        IncreaseTxtDataPosition(sizeof(uint8_t) + length);

        // Silently skip over an empty string or if the string starts with
        // a `=` character (i.e., missing key) - RFC 6763 - section 6.4.

        if ((length == 0) || (cur[0] == kKeyValueSeparator))
        {
            continue;
        }

        for (index = 0; index < length; index++)
        {
            if (cur[index] == kKeyValueSeparator)
            {
                keyBuffer[index++]  = kNullChar; // Increment index to skip over `=`.
                aEntry.mValue       = reinterpret_cast<const uint8_t *>(&cur[index]);
                aEntry.mValueLength = length - index;
                ExitNow();
            }

            if (index >= sizeof(mChar) - 1)
            {
                // The key is larger than supported key string length.
                // In this case, we return the full encoded string in
                // `mValue` and `mValueLength` and set `mKey` to
                // `nullptr`.

                aEntry.mKey         = nullptr;
                aEntry.mValue       = reinterpret_cast<const uint8_t *>(cur);
                aEntry.mValueLength = length;
                ExitNow();
            }

            keyBuffer[index] = cur[index];
        }

        // If we reach the end of the string without finding `=` then
        // it is a boolean key attribute (encoded as "key").

        keyBuffer[index]    = kNullChar;
        aEntry.mValue       = nullptr;
        aEntry.mValueLength = 0;
        ExitNow();
    }

    error = kErrorNotFound;

exit:
    return error;
}

Error TxtEntry::AppendTo(Message &aMessage) const
{
    Appender appender(aMessage);

    return AppendTo(appender);
}

Error TxtEntry::AppendTo(Appender &aAppender) const
{
    Error    error = kErrorNone;
    uint16_t keyLength;
    char     separator = kKeyValueSeparator;

    if (mKey == nullptr)
    {
        VerifyOrExit((mValue != nullptr) && (mValueLength != 0));
        error = aAppender.AppendBytes(mValue, mValueLength);
        ExitNow();
    }

    keyLength = StringLength(mKey, static_cast<uint16_t>(kMaxKeyValueEncodedSize) + 1);

    VerifyOrExit(kMinKeyLength <= keyLength, error = kErrorInvalidArgs);

    if (mValue == nullptr)
    {
        // Treat as a boolean attribute and encoded as "key" (with no `=`).
        SuccessOrExit(error = aAppender.Append<uint8_t>(static_cast<uint8_t>(keyLength)));
        error = aAppender.AppendBytes(mKey, keyLength);
        ExitNow();
    }

    // Treat as key/value and encode as "key=value", value may be empty.

    VerifyOrExit(mValueLength + keyLength + sizeof(char) <= kMaxKeyValueEncodedSize, error = kErrorInvalidArgs);

    SuccessOrExit(error = aAppender.Append<uint8_t>(static_cast<uint8_t>(keyLength + mValueLength + sizeof(char))));
    SuccessOrExit(error = aAppender.AppendBytes(mKey, keyLength));
    SuccessOrExit(error = aAppender.Append(separator));
    error = aAppender.AppendBytes(mValue, mValueLength);

exit:
    return error;
}

Error TxtEntry::AppendEntries(const TxtEntry *aEntries, uint16_t aNumEntries, Message &aMessage)
{
    Appender appender(aMessage);

    return AppendEntries(aEntries, aNumEntries, appender);
}

Error TxtEntry::AppendEntries(const TxtEntry *aEntries, uint16_t aNumEntries, MutableData<kWithUint16Length> &aData)
{
    Error    error;
    Appender appender(aData.GetBytes(), aData.GetLength());

    SuccessOrExit(error = AppendEntries(aEntries, aNumEntries, appender));
    appender.GetAsData(aData);

exit:
    return error;
}

Error TxtEntry::AppendEntries(const TxtEntry *aEntries, uint16_t aNumEntries, Appender &aAppender)
{
    Error error = kErrorNone;

    for (uint16_t index = 0; index < aNumEntries; index++)
    {
        SuccessOrExit(error = aEntries[index].AppendTo(aAppender));
    }

    if (aAppender.GetAppendedLength() == 0)
    {
        error = aAppender.Append<uint8_t>(0);
    }

exit:
    return error;
}

Error TxtDataEncoder::AppendBytesEntry(const char *aKey, const void *aBuffer, uint8_t aLength)
{
    return TxtEntry(aKey, reinterpret_cast<const uint8_t *>(aBuffer), aLength).AppendTo(mAppender);
}

Error TxtDataEncoder::AppendStringEntry(const char *aKey, const char *aStringValue)
{
    Error    error;
    uint16_t length = StringLength(aStringValue, kMaxStringEntryLength + 1);

    VerifyOrExit(length <= kMaxStringEntryLength, error = kErrorInvalidArgs);

    error = AppendBytesEntry(aKey, aStringValue, static_cast<uint8_t>(length));

exit:
    return error;
}

bool AaaaRecord::IsValid(void) const
{
    return GetType() == Dns::ResourceRecord::kTypeAaaa && GetSize() == sizeof(*this);
}

bool KeyRecord::IsValid(void) const { return GetType() == Dns::ResourceRecord::kTypeKey; }

#if OPENTHREAD_CONFIG_SRP_SERVER_ENABLE
void Ecdsa256KeyRecord::Init(void)
{
    KeyRecord::Init();
    SetAlgorithm(kAlgorithmEcdsaP256Sha256);
}

bool Ecdsa256KeyRecord::IsValid(void) const
{
    return KeyRecord::IsValid() && GetLength() == sizeof(*this) - sizeof(ResourceRecord) &&
           GetAlgorithm() == kAlgorithmEcdsaP256Sha256;
}
#endif

bool SigRecord::IsValid(void) const
{
    return GetType() == Dns::ResourceRecord::kTypeSig && GetLength() >= sizeof(*this) - sizeof(ResourceRecord);
}

void LeaseOption::InitAsShortVariant(uint32_t aLeaseInterval)
{
    SetOptionCode(kUpdateLease);
    SetOptionLength(kShortLength);
    SetLeaseInterval(aLeaseInterval);
}

void LeaseOption::InitAsLongVariant(uint32_t aLeaseInterval, uint32_t aKeyLeaseInterval)
{
    SetOptionCode(kUpdateLease);
    SetOptionLength(kLongLength);
    SetLeaseInterval(aLeaseInterval);
    SetKeyLeaseInterval(aKeyLeaseInterval);
}

bool LeaseOption::IsValid(void) const
{
    bool isValid = false;

    VerifyOrExit((GetOptionLength() == kShortLength) || (GetOptionLength() >= kLongLength));
    isValid = (GetLeaseInterval() <= GetKeyLeaseInterval());

exit:
    return isValid;
}

Error LeaseOption::ReadFrom(const Message &aMessage, uint16_t aOffset, uint16_t aLength)
{
    Error    error = kErrorNone;
    uint16_t endOffset;

    VerifyOrExit(static_cast<uint32_t>(aOffset) + aLength <= aMessage.GetLength(), error = kErrorParse);

    endOffset = aOffset + aLength;

    while (aOffset < endOffset)
    {
        uint16_t size;

        SuccessOrExit(error = aMessage.Read(aOffset, this, sizeof(Option)));

        VerifyOrExit(aOffset + GetSize() <= endOffset, error = kErrorParse);

        size = static_cast<uint16_t>(GetSize());

        if (GetOptionCode() == kUpdateLease)
        {
            VerifyOrExit(GetOptionLength() >= kShortLength, error = kErrorParse);

            IgnoreError(aMessage.Read(aOffset, this, Min(size, static_cast<uint16_t>(sizeof(LeaseOption)))));
            VerifyOrExit(IsValid(), error = kErrorParse);

            ExitNow();
        }

        aOffset += size;
    }

    error = kErrorNotFound;

exit:
    return error;
}

Error PtrRecord::ReadPtrName(const Message &aMessage,
                             uint16_t      &aOffset,
                             char          *aLabelBuffer,
                             uint8_t        aLabelBufferSize,
                             char          *aNameBuffer,
                             uint16_t       aNameBufferSize) const
{
    Error    error       = kErrorNone;
    uint16_t startOffset = aOffset - sizeof(PtrRecord); // start of `PtrRecord`.

    // Verify that the name is within the record data length.
    SuccessOrExit(error = Name::ParseName(aMessage, aOffset));
    VerifyOrExit(aOffset <= startOffset + GetSize(), error = kErrorParse);

    aOffset = startOffset + sizeof(PtrRecord);
    SuccessOrExit(error = Name::ReadLabel(aMessage, aOffset, aLabelBuffer, aLabelBufferSize));

    if (aNameBuffer != nullptr)
    {
        SuccessOrExit(error = Name::ReadName(aMessage, aOffset, aNameBuffer, aNameBufferSize));
    }

    aOffset = startOffset;
    error   = SkipRecord(aMessage, aOffset);

exit:
    return error;
}

Error TxtRecord::ReadTxtData(const Message &aMessage,
                             uint16_t      &aOffset,
                             uint8_t       *aTxtBuffer,
                             uint16_t      &aTxtBufferSize) const
{
    Error error = kErrorNone;

    SuccessOrExit(error = aMessage.Read(aOffset, aTxtBuffer, Min(GetLength(), aTxtBufferSize)));
    aOffset += GetLength();

    VerifyOrExit(GetLength() <= aTxtBufferSize, error = kErrorNoBufs);
    aTxtBufferSize = GetLength();
    VerifyOrExit(VerifyTxtData(aTxtBuffer, aTxtBufferSize, /* aAllowEmpty */ true), error = kErrorParse);

exit:
    return error;
}

bool TxtRecord::VerifyTxtData(const uint8_t *aTxtData, uint16_t aTxtLength, bool aAllowEmpty)
{
    bool    valid          = false;
    uint8_t curEntryLength = 0;

    // Per RFC 1035, TXT-DATA MUST have one or more <character-string>s.
    VerifyOrExit(aAllowEmpty || aTxtLength > 0);

    for (uint16_t i = 0; i < aTxtLength; ++i)
    {
        if (curEntryLength == 0)
        {
            curEntryLength = aTxtData[i];
        }
        else
        {
            --curEntryLength;
        }
    }

    valid = (curEntryLength == 0);

exit:
    return valid;
}

void NsecRecord::TypeBitMap::AddType(uint16_t aType)
{
    if ((aType >> 8) == mBlockNumber)
    {
        uint8_t  type  = static_cast<uint8_t>(aType & 0xff);
        uint8_t  index = (type / kBitsPerByte);
        uint16_t mask  = (0x80 >> (type % kBitsPerByte));

        mBitmaps[index] |= mask;
        mBitmapLength = Max<uint8_t>(mBitmapLength, index + 1);
    }
}

bool NsecRecord::TypeBitMap::ContainsType(uint16_t aType) const
{
    bool     contains = false;
    uint8_t  type     = static_cast<uint8_t>(aType & 0xff);
    uint8_t  index    = (type / kBitsPerByte);
    uint16_t mask     = (0x80 >> (type % kBitsPerByte));

    VerifyOrExit((aType >> 8) == mBlockNumber);

    VerifyOrExit(index < mBitmapLength);

    contains = (mBitmaps[index] & mask);

exit:
    return contains;
}

} // namespace Dns
} // namespace ot
