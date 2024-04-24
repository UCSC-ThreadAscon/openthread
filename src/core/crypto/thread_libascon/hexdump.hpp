#ifndef HEX_DUMP_H
#define HEX_DUMP_H

#include <openthread/logging.h>
#include "crypto/thread_ascon.hpp"

#define HEX_DUMP_DEBUG 1

void hexDump(void *data, uint16_t dataLength, const char* title);

#endif // HEX_DUMP_H