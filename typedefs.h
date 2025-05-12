#ifndef TYPEDEFS_H
#define TYPEDEFS_H

/* Headers required by this header */

#include <stdint.h>

/* If bool is a macro, get rid of it */

#ifdef bool
#undef bool
#undef true
#undef false
#endif

/* Typedefs */

typedef enum bool
{
  false,
  true
} bool;

typedef struct savedq
{
  struct savedq *next;
  struct savedq *prev;
  double stamp;
  uint16_t ID;
  char NAME[256];
  char pname[256];
} savedq;

typedef struct
{
  void *next;
  void *prev;
} chainbase;

#endif
