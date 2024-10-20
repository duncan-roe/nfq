#ifndef LOGGER_H
#define LOGGER_H

/* Headers required by this header */

#include <stdio.h>
#include "prototypes.h"

/* Macros */

#define LOG(fmt, args...) \
do { snprintf(log_buffer, sizeof log_buffer, fmt, ##args); logger(); } while (0)

/* External variables */

extern char log_buffer[32768];
extern double time_now;
extern double base_time;           /* Add to time_now to get wall clock */
extern FILE *logfile;
extern bool hupseen;

#endif
