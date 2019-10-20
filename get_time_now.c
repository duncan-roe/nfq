/* T I M E _ N O W . C
 *
 * Copyright (C) 2019 Duncan Roe */

/* Headers */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include "prototypes.h"
#include "logger.h"
#include "typedefs.h"

/* Macros */

#ifdef CLOCK_MONOTONIC_RAW
#define Q_CLOCK CLOCK_MONOTONIC_RAW
#else
#define Q_CLOCK CLOCK_MONOTONIC
#endif
#define GTOD_INTERVAL 30           /* Re-issue gtod in case external change */

/* Instantiate Externals */

double base_time = 0;
double time_now = 0;
char log_buffer[32768];

/* Static Variables */

static bool first_call = true;
static double last_gtod = 0;

/* ****************************** get_time_now ****************************** */

bool
get_time_now(void)
{
  struct timespec tp;
  struct timeval tv;

  if (clock_gettime(Q_CLOCK, &tp))
  {
    fprintf(stderr, "%s. CLOCK_MONOTONIC_RAW (clock_gettime)\n",
      strerror(errno));
    return false;
  }                                /* if (clock_gettime(Q_CLOCK, &tp)) */
  time_now = (double)tp.tv_sec + tp.tv_nsec / 1000000000.0;

  if (first_call || time_now - last_gtod > GTOD_INTERVAL)
  {
    if (gettimeofday(&tv, NULL))
    {
      fprintf(stderr, "%s. (gettimeofday)\n", strerror(errno));
      return false;
    }                              /* if (gettimeofday(*tv, NULL)) */
    base_time = (double)tv.tv_sec + tv.tv_usec / 1000000.0 - time_now;

    last_gtod = time_now;
    first_call = false;
  }                                /* if (was_first_call... */

  return true;
}                                  /* bool get_time_now(void) */
