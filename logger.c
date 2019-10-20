/* L O G G E R
 *
 * Copyright (C) 2019 Duncan Roe
 *
 * Output the log buffer with a timestamp */

#include <time.h>
#include "logger.h"

void logger()
{
  char tbuf[64];
  time_t timep = time_now + base_time;

  strftime(tbuf, sizeof tbuf, "%b %d %T", localtime(&timep));
  printf("%s %s", tbuf, log_buffer);
}                                  /* void logger() */
