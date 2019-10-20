/* chains.c - the traditional chain & unchain routines as used by GFE */
/* Copyright (c) 2003 Geoscience Australia
 * Author: Duncan Roe */

#include "prototypes.h"
#ifndef NULL
#define NULL (void*)0
#endif

typedef struct hddr                /* Used by the chaining routines */
{
  struct hddr *next;
  struct hddr *prev;
} hddr;                            /* typedef struct hddr */

/* ****************************** gfechain ****************************** */

/* Chain block A1 after block A2 */

void
gfechain(void *new, void *old)
{
  ((hddr *)new)->next = ((hddr *)old)->next;
  ((hddr *)new)->prev = (hddr *)old;
  ((hddr *)new)->next->prev = (hddr *)new;
  ((hddr *)old)->next = (hddr *)new;
}                                  /* static void gfechain(void*old,void,new) */

/* ****************************** gfeunchn ****************************** */

/* Unchain block A1 */

void *
gfeunchn(void *new)
{
  ((hddr *)new)->next->prev = ((hddr *)new)->prev;
  ((hddr *)new)->prev->next = ((hddr *)new)->next;
  ((hddr *)new)->next = NULL;      /* Npt chained now */
  ((hddr *)new)->prev = NULL;      /* Npt chained now */
  return new;
}                                  /* static void gfeunchn(void*new) */
