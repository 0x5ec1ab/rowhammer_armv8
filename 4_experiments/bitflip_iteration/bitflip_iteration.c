/**
  * bitflip_iteration -- find relationship between #bitflip and #iteration
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
#define OUT_INTERVAL  10

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
unsigned long temp = -1;
unsigned long samp_pts[] = {5000000, 4000000, 3000000, 2500000, 2000000,
  1500000, 1000000, 900000, 800000, 700000, 600000, 500000, 400000, 300000,
  200000, 100000, 80000, 70000, 60000, 50000,
  40000, 30000, 20000, 10000, 5000, 1000};
unsigned long samp_len;

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
    } else
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
    } else if (head == NULL){
      head = curr;
      prev = head;
    } else {
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
  unsigned i, j, k;
  unsigned long addr1, addr2;
  FILE *fp, *fcnt;
  char path[200];
  sprintf(path, "/proc/%u/pagemap", getpid());
  int pgmp = open(path, O_RDONLY);
  unsigned long vctm_pa, *vctm_va, val;
  char str[999];
  struct attkr_t *head, *curr;
  unsigned long prev_init = -1;

  // initialize chunk
  for (i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
    chunk[i] = -1;
  // generate pa-va mapping
  generate_va_table(pgmp);
  head = generate_addr_list(INPUT_FILE);

  unsigned long h_rnd;
  samp_len = sizeof(samp_pts) / sizeof(unsigned long);
  
  // START
  fp = fopen("results/addr_cvac_str.txt", "w");
  fcnt = fopen("results/cnt_cvac_str.txt","w");
  printf("civac_ldr\n");
  for (k = 0; k < samp_len; k++){
    h_rnd = samp_pts[k];
    fprintf(fp,"rnd: %lu\n", h_rnd);
    fprintf(fcnt,"%lu\t", h_rnd);
    printf("round %lu\n", h_rnd);
    i = 0;
    cnt = 0;
    for(curr = head; curr != NULL; curr = curr->next){
      addr1 = curr->va1;
      addr2 = curr->va2;
      if (addr1 == 0 || addr2 == 0)
        continue;
      i++;
      if (prev_init != curr->init_val){
        printf("change check bit to %lx\n", curr->init_val);
        memset(chunk, curr->init_val, CHUNK_SIZE);
        prev_init = curr->init_val;
      }
      temp = curr->init_val;
      // DIFF
      for (int i = 0; i < h_rnd; ++i) {
        asm volatile(
          "str %2, [%0]\n\t"
          "str %2, [%1]\n\t"
          "dc cvac, %0\n\t"
          "dc cvac, %1\n\t"
          ::"r" (addr1), "r" (addr2), "r" (temp)
        );
      }
      // DIFF
      for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
        // check victim row only
        vctm_pa = curr->vctm_base + j; vctm_va = pa_to_va(vctm_pa);
        if (vctm_va == 0)
          continue;
        val = *vctm_va;
        if (val != curr->init_val) {
          cnt++;
          printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
          printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
          fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        }
        *vctm_va = curr->init_val;
      }
      if (i % OUT_INTERVAL == 0 )
        printf("round:%u\tcount:%u\n\n", i, cnt);
    }
    fprintf(fcnt,"%u\t%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END
  
  // START
  fp = fopen("results/addr_zva.txt", "w");
  fcnt = fopen("results/cnt_zva.txt","w");
  printf("zva\n");
  for (k = 0; k < samp_len; k++){
    h_rnd = samp_pts[k];
    fprintf(fp,"rnd: %lu\n", h_rnd);
    fprintf(fcnt,"%lu\t", h_rnd);
    printf("round %lu\n", h_rnd);
    i = 0;
    cnt = 0;
    for(curr = head; curr != NULL; curr = curr->next){
      addr1 = curr->va1;
      addr2 = curr->va2;
      if (addr1 == 0 || addr2 == 0)
        continue;
      i++;
      if (prev_init != curr->init_val){
        printf("change check bit to %lx\n", curr->init_val);
        memset(chunk, curr->init_val, CHUNK_SIZE);
        prev_init = curr->init_val;
      }
      temp = curr->init_val;
      // DIFF
      asm volatile(
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        ::"r" (addr1), "r" (addr2)
      );
      for (int i = 0; i < h_rnd; ++i) {
        asm volatile(
          "dc zva, %0\n\t"
          "dc zva, %1\n\t"
          ::"r" (addr1), "r" (addr2)
        );
      }
      // DIFF
      for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
        // check victim row only
        vctm_pa = curr->vctm_base + j; vctm_va = pa_to_va(vctm_pa);
        if (vctm_va == 0)
          continue;
        val = *vctm_va;
        if (val != curr->init_val) {
          cnt++;
          printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
          printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
          fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        }
        *vctm_va = curr->init_val;
      }
      if (i % OUT_INTERVAL == 0 )
        printf("round:%u\tcount:%u\n\n", i, cnt);
    }
    fprintf(fcnt,"%u\t%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_civac_ldr.txt", "w");
  fcnt = fopen("results/cnt_civac_ldr.txt","w");
  printf("civac_ldr\n");
  for (k = 0; k < samp_len; k++){
    h_rnd = samp_pts[k];
    fprintf(fp,"rnd: %lu\n", h_rnd);
    fprintf(fcnt,"%lu\t", h_rnd);
    printf("round %lu\n", h_rnd);
    i = 0;
    cnt = 0;
    for(curr = head; curr != NULL; curr = curr->next) {
      addr1 = curr->va1;
      addr2 = curr->va2;
      if (addr1 == 0 || addr2 == 0)
        continue;
      i++;
      if (prev_init != curr->init_val) {
        printf("change check bit to %lx\n", curr->init_val);
        memset(chunk, curr->init_val, CHUNK_SIZE);
        prev_init = curr->init_val;
      }
      temp = curr->init_val;
      // DIFF
      for (int i = 0; i < h_rnd; ++i) {
        asm volatile(
          "ldr %2, [%0]\n\t"
          "ldr %2, [%1]\n\t"
          "dc civac, %0\n\t"
          "dc civac, %1\n\t"
          ::"r" (addr1), "r" (addr2), "r" (temp)
        );
      }
      // DIFF
      for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
        // check victim row only
        vctm_pa = curr->vctm_base + j; vctm_va = pa_to_va(vctm_pa);
        if (vctm_va == 0)
          continue;
        val = *vctm_va;
        if (val != curr->init_val) {
          cnt++;
          printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
          printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
          fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        }
        *vctm_va = curr->init_val;
      }
      if (i % OUT_INTERVAL == 0 )
        printf("round:%u\tcount:%u\n\n", i, cnt);
    }
    fprintf(fcnt,"%u\t%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  // START
  fp = fopen("results/addr_civac_str.txt", "w");
  fcnt = fopen("results/cnt_civac_str.txt","w");
  printf("civac_ldr\n");
  for (k = 0; k < samp_len; k++){
    h_rnd = samp_pts[k];
    fprintf(fp,"rnd: %lu\n", h_rnd);
    fprintf(fcnt,"%lu\t", h_rnd);
    printf("round %lu\n", h_rnd);
    i = 0;
    cnt = 0;
    for(curr = head; curr != NULL; curr = curr->next){
      addr1 = curr->va1;
      addr2 = curr->va2;
      if (addr1 == 0 || addr2 == 0)
        continue;
      i++;
      if (prev_init != curr->init_val){
        printf("change check bit to %lx\n", curr->init_val);
        memset(chunk, curr->init_val, CHUNK_SIZE);
        prev_init = curr->init_val;
      }
      temp = curr->init_val;
      // DIFF
      for (int i = 0; i < h_rnd; ++i) {
        asm volatile(
          "str %2, [%0]\n\t"
          "str %2, [%1]\n\t"
          "dc civac, %0\n\t"
          "dc civac, %1\n\t"
          ::"r" (addr1), "r" (addr2), "r" (temp)
        );
      }
      // DIFF
      for (j = 0; j < ROW_SIZE; j += VAL_SIZE) {
        // check victim row only
        vctm_pa = curr->vctm_base + j; vctm_va = pa_to_va(vctm_pa);
        if (vctm_va == 0)
          continue;
        val = *vctm_va;
        if (val != curr->init_val) {
          cnt++;
          printf("attkr1:%lx\tattkr2:%lx\n", curr->pa1, curr->pa2);
          printf("rnd:%u\tcnt:%u\tvctm:%lx to %lx\n", i, cnt, vctm_pa, val);
          fprintf(fp,"%lx\t%lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        }
        *vctm_va = curr->init_val;
      }
      if (i % OUT_INTERVAL == 0 )
        printf("round:%u\tcount:%u\n\n", i, cnt);
    }
    fprintf(fcnt,"%u\t%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);
  // END

  close(pgmp);
}

