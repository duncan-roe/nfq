/* L O G G E R
 *
 * Copyright (C) 2019, 2024 Duncan Roe
 *
 * Output the log buffer with a timestamp
 * Manage log file initial open and re-open on SIGHUP
 */

/* Headers */

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

/* Static Variables */

static const char *const logname = "/var/log/nfqlog";

void logger()
{
  char tbuf[64];
  time_t timep = time_now + base_time;

/* Open / re-open log file if required */
  if (hupseen)
  {
    if(logfile)                    /* Only gets opened after msg rx'd */
      fclose(logfile);
    logfile = NULL;
    hupseen = false;
    re_read_config = true;
  }                                /* if (hupseen) */
  if (!logfile)
  {
    logfile = fopen(logname, "a");
    if (!logfile)
    {
      fprintf(stderr, "%s. %s (fopen)\n", strerror(errno), logname);
      exit(EXIT_FAILURE);
    }                              /* if (!logfile) */
    setlinebuf(logfile);
  }                                /* if (!logfile) */

  strftime(tbuf, sizeof tbuf, "%b %d %T", localtime(&timep));
  fprintf(logfile, "%s %s", tbuf, log_buffer);
}                                  /* void logger() */
