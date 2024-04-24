#include "hexdump.hpp"

#include <openthread/logging.h>
#include "crypto/thread_ascon.hpp"

void printHexDump(otLogHexDumpInfo *aInfo) {
  otError error = OT_ERROR_NONE;

  while (error == OT_ERROR_NONE) {
    error = otLogGenerateNextHexDumpLine(aInfo);

    if (error == OT_ERROR_NONE) {
      otLogNotePlat("%s", aInfo->mLine);
    }
    else if (error != OT_ERROR_NOT_FOUND) {
      otLogCritPlat(otThreadErrorToString(error));
    }
  }

  return;
}

void hexDump(void *data, uint16_t dataLength, const char* title) {
  otLogHexDumpInfo keyHexDump;
  EmptyMemory(&keyHexDump, sizeof(otLogHexDumpInfo));

  keyHexDump.mDataBytes = (uint8_t *) data;
  keyHexDump.mDataLength = dataLength;
  keyHexDump.mTitle = title;

  printHexDump(&keyHexDump);
  return;
}