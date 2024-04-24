#include "hexdump.h"

#include <openthread/logging.h>
#include "crypto/thread_ascon.hpp"

void hexDumpKey(void *asconKey) {
  otLogHexDumpInfo keyHexDump;
  EmptyMemory(keyHexDump);

  keyHexDump.mDataBytes = asconKey;
  keyHexDump.mDataLength = OT_NETWORK_KEY_SIZE;
  keyHexDump.mTitle = "Thread Network Key Bytes";

  otLogGenerateNextHexDumpLine(&keyHexDump);
  return;
}