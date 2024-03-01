/**
 * The ASCON C Implementation was written by:
 *
 *  Christoph Dobraunig
 *  Martin Schläffer
*/
#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_

#define ASCON_PRINT_STATE 0

#if (ASCON_PRINT_STATE == 1)

#include "ascon.hpp"
#include "ascon_word.hpp"

void printword(const char* text, const uint64_t x);
void printstate(const char* text, const ascon_state_t* s);

#else

#define printword(text, w) \
  do {                     \
  } while (0)

#define printstate(text, s) \
  do {                      \
  } while (0)

#endif

#endif /* PRINTSTATE_H_ */
