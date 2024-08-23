#include "hexdump.hpp"

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
  otLogHexDumpInfo hexDumpInfo;
  EmptyMemory(&hexDumpInfo, sizeof(otLogHexDumpInfo));

  hexDumpInfo.mDataBytes = (uint8_t *) data;
  hexDumpInfo.mDataLength = dataLength;
  hexDumpInfo.mTitle = title;

  printHexDump(&hexDumpInfo);
  return;
}