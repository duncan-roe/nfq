/* chains.h - Macros to assist chaining */
/* Author: Duncan Roe */
#ifndef CHAINS_H
#define CHAINS_H

/* ------------------------------------------------------------------- */
/* The FOREACH macro sets up a "for" loop in which "x" is a pointer to */
/* each successive structure in chain with base "y".                   */
/* The loop terminates when the pointer advances back to the chainbase */
/* ------------------------------------------------------------------- */

#define FOREACH(x, y) for ((x) = (y).next; !ATBASE((x), (y)); (x) = (x)->next)

/* ----------------------------------------------------------------------- */
/* The ATBASE macro returns TRUE iff the pointer "x" is at chainbase "y".  */
/* The arguments of ATBASE are deliberately identical to those of FOREACH, */
/* so that the two can easily be used in conjunction.                      */
/* ----------------------------------------------------------------------- */

#define ATBASE(x, y) ((x) == (void *)&(y))

/* ------------------------------------------------------------------- */
/* FOREACHBACK is like FOREACH except it goes backward round the chain */
/* ------------------------------------------------------------------- */

#define \
  FOREACHBACK(x, y) for ((x) = (y).prev; !ATBASE((x), (y)); (x) = (x)->prev)

/* ---------------------------------------------------------------- */
/* The GFEUNCHN macro may be used inside or outside a FOREACH loop, */
/* to unchain the currently accessed chain element.                 */
/* gfeunchn(x) is not safe in this regard,                          */
/* as it leaves (x) pointing to an indeterminate location.          */
/* ---------------------------------------------------------------- */

#define GFEUNCHN(x) gfeunchn(((x)=(x)->prev)->next)

#endif
