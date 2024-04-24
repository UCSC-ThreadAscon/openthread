#ifndef HEX_DUMP_H
#define HEX_DUMP_H

#include <openthread/logging.h>
#include "crypto/thread_ascon.hpp"

void hexDump(void *data, uint16_t dataLength, const char* title);

#endif // HEX_DUMP_H