/**
 * The ASCON C Implementation was written by:
 *
 *  Christoph Dobraunig
 *  Martin Schläffer
*/

#include "ascon_printstate.hpp"

#if (ASCON_PRINT_STATE == 1)

#include <openthread/logging.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifndef WORDTOU64
#define WORDTOU64
#endif

#ifndef U64BIG
#define U64BIG
#endif

void printword(const char* text, const uint64_t x) {
  otLogNotePlat("%s=%016" PRIx64, text, U64BIG(WORDTOU64(x)));
}

void printstate(const char* text, const ascon_state_t* s) {
  int i;
  otLogNotePlat("%s:", text);
  for (i = strlen(text); i < 17; ++i) otLogNotePlat(" ");
  printword(" x0", s->x[0]);
  printword(" x1", s->x[1]);
  printword(" x2", s->x[2]);
  printword(" x3", s->x[3]);
  printword(" x4", s->x[4]);
  otLogNotePlat("\n");
}

#endif
