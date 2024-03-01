#include "cse299a_encryption_flags.h"

void mleEncryptPrintTransmitted() {
  if (AES_MLE_ENCRYPT) {
    otLogNotePlat("(MLE Encrypt ON) Transmit Frame.");
  } else {
    otLogNotePlat("(MLE Encrypt OFF) Transmit Frame.");
  }
  return;
}

void mleDecryptPrintReceived() {
  if (AES_MLE_DECRYPT) {
    otLogNotePlat("(MLE Decrypt ON) Received Frame.");
  } else {
    otLogNotePlat("(MLE Decrypt OFF) Received Frame.");
  }
  return;
}