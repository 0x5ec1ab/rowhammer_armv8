#ifndef ROWHAMMER_PAGEMAP_H
#define ROWHAMMER_PAGEMAP_H

typedef struct candidate {
  unsigned long pa1;
  unsigned long va1;
  unsigned long pa2;
  unsigned long va2;
  struct candidate *next;
} candidate_t;

candidate_t *
find_candidates(unsigned long, unsigned long, unsigned, unsigned);

void
cleanup_candidates(candidate_t *);

#endif

