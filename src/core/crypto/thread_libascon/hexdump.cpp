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

void hexDumpKey(void *asconKey) {
  otLogHexDumpInfo keyHexDump;
  EmptyMemory(&keyHexDump, sizeof(otLogHexDumpInfo));

  keyHexDump.mDataBytes = (uint8_t *) asconKey;
  keyHexDump.mDataLength = OT_NETWORK_KEY_SIZE;
  keyHexDump.mTitle = "Thread Network Key Bytes";

  otLogNotePlat("Supposed to generate hex dump.");
  printHexDump(&keyHexDump);
  return;
}