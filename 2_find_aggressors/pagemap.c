/**
  * pagemap -- find candidate aggressor rows to hammer
  * By VandySec Group
**/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "pagemap.h"

candidate_t *
find_candidates(unsigned long addr_bgn, unsigned long addr_end,
    unsigned page_bits, unsigned target_bit)
{
  unsigned i;
  unsigned page_size = 1 << page_bits;
  pid_t pid = getpid();
  FILE *fp;
  char path[200];
  unsigned long va;
  unsigned long pa;
  uint64_t offset;
  uint64_t val;
  uint64_t pfn;
  
  candidate_t *head = NULL;
  candidate_t *temp = NULL;
  candidate_t *prev;
  candidate_t *curr;
  
  // if page_bits is 12, then 11...0 are used for page offset
  if (addr_end <= addr_bgn || target_bit < page_bits) {
    printf("not well-defined arguments\n");
    exit(-1);
  }
  
  sprintf(path, "/proc/%u/pagemap", pid);
  fp = fopen(path, "rb");
  
  va = addr_bgn >> page_bits;
  va <<= page_bits;
  if (va < addr_bgn)
    va += page_size;
  
  while (va < addr_end) {
    offset = va / page_size * 8;
    fseek(fp, offset, SEEK_SET);
    val = 0;
    for (i = 0; i < 8; ++i) {
      unsigned char c = getc(fp);
      val |= ((uint64_t) c << (8 * i));
    }
    
    if (val & 0x8000000000000000 == 0) {
      printf("some page is not in memory yet\n");
      exit(-1);
    }
    
    pfn = val & 0x7FFFFFFFFFFFFF;
    pa = pfn << page_bits;
    
    prev = NULL;
    curr = temp;
    while (curr != NULL) {
      if ((pa ^ curr->pa1) != (1 << target_bit)) {
        prev = curr;
        curr = curr->next;
        continue;
      }
      // matching candidate is found, so move it into another list
      curr->pa2 = pa;
      curr->va2 = va;
      if (prev != NULL)
        prev->next = curr->next;
      else
        temp = curr->next;
      curr->next = head;
      head = curr;
      break;
    }
    
    // if we didn't find a matching candidate
    if (curr == NULL) {
      curr = (candidate_t *) malloc(sizeof(candidate_t));
      curr->pa1 = pa;
      curr->va1 = va;
      curr->next = temp;
      temp = curr;
    }
    
    va += page_size;
  }
  
  cleanup_candidates(temp);
  return head;
}

void
cleanup_candidates(candidate_t *head)
{
  candidate_t *curr;
  while (head != NULL) {
    curr = head;
    head = head->next;
    free(curr);
  }
}

