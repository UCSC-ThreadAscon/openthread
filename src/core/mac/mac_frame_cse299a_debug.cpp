#include "cse299a_encryption_flags.h"

void dataDecryptPrintReceived() {
  if (AES_DATA_DECRYPT) {
    otLogNotePlat("(Data Decrypt ON) Received Frame.");
  } else if (ASCON_DATA_DECRYPT) {
    otLogNotePlat("(Data Decrypt ASCON) Received Frame.");
  } else {
    otLogNotePlat("(Data Decrypt OFF) Received Frame.");
  }
  return;
}