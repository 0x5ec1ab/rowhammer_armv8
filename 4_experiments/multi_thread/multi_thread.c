/**
  * multi_thread -- show effectiveness of multi thread
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
#define OUT_INTERVAL  1

// input arguments for thread routine
//  address to be hammered
//  the core on which the thread runs
struct thr_arg {
  unsigned long addr;
  unsigned long core;
};
// linked list for storing attacker addresses
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
struct unibit_t *bit_head = NULL;
pthread_cond_t cv;
pthread_mutex_t mtx;
int status_arr[4];
unsigned long temp = -1;

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

// thread entry
void *
civac_str_wo(void *argp)
{
  struct thr_arg data = *(struct thr_arg *)argp;
  int addr = data.addr;
  int core = data.core;
  cpu_set_t cs;
  pthread_t tself;
  // set core affinity
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  
  pthread_mutex_lock(&mtx);
  // ready to begin
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  // begin hammering
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "str %1, [%0]\n\t"
      "dc civac, %0\n\t"
      ::"r" (addr), "r" (temp)
    );
  }
}
void *
civac_ldr_wo(void *argp)
{
  struct thr_arg data = *(struct thr_arg *)argp;
  int addr = data.addr;
  int core = data.core;
  cpu_set_t cs;
  pthread_t tself;
  // set core affinity
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  
  pthread_mutex_lock(&mtx);
  // ready to begin
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  // begin hammering
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "ldr %1, [%0]\n\t"
      "dc civac, %0\n\t"
      ::"r" (addr), "r" (temp)
    );
  }
}

int
main(int argc, char **argv)
{ unsigned i, j;
  unsigned flips = 0;
  unsigned long addr1, addr2;
  FILE *fp, *fcnt;
  char path[200];
  sprintf(path, "/proc/%u/pagemap", getpid());
  int pgmp = open(path, O_RDONLY);
  unsigned long vctm_pa, *vctm_va, val;
  char str[999];
  struct attkr_t *head, *curr;
  unsigned long prev_init = -1;

  pthread_t tid0, tid1, tid2, tid3, tself;
  struct thr_arg arg0, arg1, arg2, arg3;
  cpu_set_t cs;
  arg0.core = 0;
  arg1.core = 1;
  arg2.core = 2;
  arg3.core = 3;
  CPU_ZERO(&cs);
  CPU_SET(0, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  pthread_cond_init(&cv, NULL);
  pthread_mutex_init(&mtx, NULL);

  // initialize chunk
  for (i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
    chunk[i] = -1;
  // generate pa-va mapping
  generate_va_table(pgmp);
  head = generate_addr_list(INPUT_FILE);
  // START
  fp = fopen("results/addr_civac_ldr_2.txt", "w");
  fcnt = fopen("results/cnt_civac_ldr_2.txt","w");
  printf("civac_ldr_2\n");
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
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_ldr_wo, &arg1);
    pthread_create(&tid2, NULL, civac_ldr_wo, &arg2);
    while(status_arr[1] != 1 || status_arr[2] !=1)
    {
      // spinlock
    }
    while(status_arr[1] == 1 || status_arr[2] ==1)
      pthread_cond_broadcast(&cv);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
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
        fprintf(fp,"%8lx %8lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
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
  fp = fopen("results/addr_civac_str_2.txt", "w");
  fcnt = fopen("results/cnt_civac_str_2.txt","w");
  printf("civac_str_2\n");
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
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_str_wo, &arg1);
    pthread_create(&tid2, NULL, civac_str_wo, &arg2);
    while(status_arr[1] != 1 || status_arr[2] !=1);
    while(status_arr[1] == 1 || status_arr[2] ==1)
      pthread_cond_broadcast(&cv);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
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
        fprintf(fp,"%8lx %8lx\t%lu\n", curr->pa1, curr->pa2, -(curr->init_val));
        fprintf(fcnt,"%u\t%u\n\n", i, cnt);
      }
      *vctm_va = curr->init_val;
    }
    if (i % OUT_INTERVAL == 0 )
      printf("round:%u\tcount:%u\n\n", i, cnt);
  }
  fclose(fp);
  fclose(fcnt);

  close(pgmp);
}

