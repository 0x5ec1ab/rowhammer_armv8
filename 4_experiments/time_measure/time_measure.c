/**
  * time_measure -- measure execution time of different approaches
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
#include <time.h>
#include <pthread.h>

#define CHUNK_SIZE    0x40000000
#define VPN_SIZE      0x80000
#define PAGE_SIZE     4096
#define VAL_SIZE      sizeof(unsigned long)
#define TIMES         1000
#define HAMMER_ROUND  2000
#define DISABLE       0

// argument for thread routine
//  address to be hammered
//  the core on which the thread runs
struct thr_arg {
  unsigned long addr;
  unsigned long core;
};

unsigned long chunk[CHUNK_SIZE / VAL_SIZE];
pthread_cond_t cv;
pthread_mutex_t mtx;
int status_arr[4];

// thread routines
void *
civac_str_wo(void *argp)
{
  struct thr_arg data = *(struct thr_arg *)argp;
  int addr = data.addr;
  int core = data.core;
  unsigned long temp = -1;
  // set core affinity
  cpu_set_t cs;
  pthread_t tself;
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  // synchronization
  pthread_mutex_lock(&mtx);
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  // repeately access and flush the same memory location
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "str %1, [%0]\n\t"
      "dc civac, %0\n\t"
      ::"r" (addr), "r" (temp)
    );
  }
}
void *
civac_str_w(void *argp)
{
  struct thr_arg data = *(struct thr_arg *)argp;
  int addr = data.addr;
  int core = data.core;
  unsigned long temp = -1;
  cpu_set_t cs;
  pthread_t tself;
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  
  pthread_mutex_lock(&mtx);
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "str %1, [%0]\n\t"
      "dc civac, %0\n\t"
      "dsb 0xb"
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
  unsigned long temp = -1;
  cpu_set_t cs;
  pthread_t tself;
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  
  pthread_mutex_lock(&mtx);
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "ldr %1, [%0]\n\t"
      "dc civac, %0\n\t"
      ::"r" (addr), "r" (temp)
    );
  }
}
void *
civac_ldr_w(void *argp)
{
  struct thr_arg data = *(struct thr_arg *)argp;
  int addr = data.addr;
  int core = data.core;
  unsigned long temp = -1;
  cpu_set_t cs;
  pthread_t tself;
  CPU_ZERO(&cs);
  CPU_SET(core, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);
  
  pthread_mutex_lock(&mtx);
  status_arr[core] = 1;
  pthread_cond_wait(&cv, &mtx);
  pthread_mutex_unlock(&mtx);
  status_arr[core] = 0;
  for (int i = 0; i < HAMMER_ROUND; ++i) {
    asm volatile(
      "ldr %1, [%0]\n\t"
      "dc civac, %0\n\t"
      "dsb 0xb"
      ::"r" (addr), "r" (temp)
    );
  }
}
int
main(int argc, char **argv)
{ 
  unsigned i, j;
  unsigned long addr1, addr2;
  unsigned long temp = -1;
  candidate_t *head, *curr;
  char path[200];
  unsigned long bgn, end;
  struct timespec ts1, ts2;
  unsigned long td;

  pthread_t tid0, tid1, tid2, tid3, tself;
  struct thr_arg arg0, arg1, arg2, arg3;
  cpu_set_t cs;
  arg0.core = 0;
  arg1.core = 1;
  arg2.core = 2;
  arg3.core = 3;
  // assign main thread on core 0
  CPU_ZERO(&cs);
  CPU_SET(0, &cs);
  tself = pthread_self();
  pthread_setaffinity_np(tself, sizeof(cpu_set_t), &cs);

  // initialize chunk
  for (i = 0; i < CHUNK_SIZE / VAL_SIZE; ++i)
    chunk[i] = -1;
  bgn = (unsigned long) chunk;
  end = bgn + CHUNK_SIZE;
  head = find_candidates(bgn, end, 12, 16);
// measure execution time per loop for 6 methods with/without memory barrier
// DC ZVA
// DC CVAC  + STR
// DC CIVAC + STR
// DC CIVAC + LDR
// DC CIVAC + STR 2 thread
// DC CIVAC + LDR 2 thread

// DC ZVA can't work when it's disabled
#if !DISABLE
  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    // two addresses to be hammered
    addr1 = curr->va1;
    addr2 = curr->va2;
    // flush two aggressor rows
    asm volatile(
      "dc civac, %0\n\t"
      "dc civac, %1\n\t"
      ::"r" (addr1), "r" (addr2)
    );
    // get time stamp before hammering
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (j = 0; j < HAMMER_ROUND; ++j) {
      // use dc zva to access target rows
      asm volatile(
        "dc zva, %0\n\t"
        "dc zva, %1\n\t"
        ::"r" (addr1), "r" (addr2)
      );
    }
    // get time stamp after hammering
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    // compute execution time per loop
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc zva       w/o\t%lu\n", td / HAMMER_ROUND / TIMES);
  // same operations for remaining 11 measurements
  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    asm volatile(
      "dc civac, %0\n\t"
      "dc civac, %1\n\t"
      ::"r" (addr1), "r" (addr2)
    );
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "dc zva, %0\n\t"
        "dc zva, %1\n\t"
        "dsb 0xb"
        ::"r" (addr1), "r" (addr2)
      );
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc zva       w/ \t%lu\n", td / HAMMER_ROUND / TIMES);
#endif

  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc cvac, %0\n\t"
        "dc cvac, %1\n\t"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc cvac      w/o\t%lu\n", td / HAMMER_ROUND / TIMES);
  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
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
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc cvac      w/ \t%lu\n", td / HAMMER_ROUND / TIMES);

  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "str %2, [%0]\n\t"
        "str %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac str w/o\t%lu\n", td / HAMMER_ROUND / TIMES);
  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
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
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac str w/ \t%lu\n", td / HAMMER_ROUND / TIMES);

  td = 0; 
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (j = 0; j < HAMMER_ROUND; ++j) {
      asm volatile(
        "ldr %2, [%0]\n\t"
        "ldr %2, [%1]\n\t"
        "dc civac, %0\n\t"
        "dc civac, %1\n\t"
        ::"r" (addr1), "r" (addr2), "r" (temp)
      );
    }
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac ldr w/o\t%lu\n", td / HAMMER_ROUND / TIMES);
  td = 0;
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
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
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac ldr w/ \t%lu\n", td / HAMMER_ROUND / TIMES);

  td = 0; 
  pthread_cond_init(&cv, NULL);
  pthread_mutex_init(&mtx, NULL);
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_str_wo, &arg1);
    pthread_create(&tid2, NULL, civac_str_wo, &arg2);
    while(status_arr[1] != 1 || status_arr[2] != 1);
    while(status_arr[1] == 1 || status_arr[2] == 1)
      pthread_cond_broadcast(&cv);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac str w/o\t%lu\tparallel\n", td / HAMMER_ROUND / TIMES);
  td = 0; 
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_str_w, &arg1);
    pthread_create(&tid2, NULL, civac_str_w, &arg2);
    while(status_arr[1] != 1 || status_arr[2] != 1);
    while(status_arr[1] == 1 || status_arr[2] == 1)
      pthread_cond_broadcast(&cv);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac str w  \t%lu\tparallel\n", td / HAMMER_ROUND / TIMES);

  td = 0; 
  pthread_cond_init(&cv, NULL);
  pthread_mutex_init(&mtx, NULL);
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_ldr_wo, &arg1);
    pthread_create(&tid2, NULL, civac_ldr_wo, &arg2);
    while(status_arr[1] != 1 || status_arr[2] != 1);
    while(status_arr[1] == 1 || status_arr[2] == 1)
      pthread_cond_broadcast(&cv);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac ldr w/o\t%lu\tparallel\n", td / HAMMER_ROUND / TIMES);
  td = 0; 
  for (i = 0, curr = head; i < TIMES && curr != NULL; ++i, curr = curr->next) {
    addr1 = curr->va1;
    addr2 = curr->va2;
    arg1.addr = addr1;
    arg2.addr = addr2;
    pthread_create(&tid1, NULL, civac_ldr_w, &arg1);
    pthread_create(&tid2, NULL, civac_ldr_w, &arg2);
    while(status_arr[1] != 1 || status_arr[2] != 1);
    while(status_arr[1] == 1 || status_arr[2] == 1)
      pthread_cond_broadcast(&cv);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td += (ts2.tv_sec - ts1.tv_sec) * 1000000000 + (ts2.tv_nsec - ts1.tv_nsec);
  }
  printf("dc civac ldr w  \t%lu\tparallel\n", td / HAMMER_ROUND / TIMES);

}

