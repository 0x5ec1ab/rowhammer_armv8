/*******************************************************************************
* two_bit_latency-armv8 -- measure the latency between accessing two addresses
  with two bits different on ARMv8
* By VandySec Group
*******************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/random.h>

#define LAT_ARRAY_SIZE 8 * 1024 * 1024
#define LAT_LENGTH 22

char array[LAT_ARRAY_SIZE];

int
module_bgn(void)
{

  int i, j, k, l;
  unsigned sum = 0;
  unsigned long writeValue = 0;
  unsigned long t1 = 0;
  unsigned long t2 = 0;
  unsigned long temp = 0;
  unsigned long basis;
  unsigned long v_addr;
  unsigned long v_addr_0;
  unsigned long v_addr_1;
  unsigned diff_bit;
  unsigned diff_bit2;
  unsigned long mask;
  //unsigned long p_addr;
  unsigned long random;
  // Start
  printk(KERN_INFO "Insert module \n");

  // Set up PMU
  // enable PMC
  writeValue = 0x80000000;
  asm volatile("MSR PMCNTENSET_EL0, %0":: "r" (writeValue));
	// Performance Control Register | 00111 | 
  // Always enable cycle counter | enable export events | 
  // disable clock divider | reset clock couner | reset event couner
  writeValue = 0x00000007;
  asm volatile("MSR PMCR_EL0, %0":: "r" (writeValue));
  
  // Initialize basis
  basis = (unsigned long) array;
  basis >>= LAT_LENGTH;
  basis += 1;
  basis <<= LAT_LENGTH;
  
  for (l = 6; l < LAT_LENGTH; l++) {
    for (k = 6; k < LAT_LENGTH; k++) {
      diff_bit = k;
      diff_bit2 = l;
      mask = (1 << diff_bit) | (1 << diff_bit2);
      for (j = 0; j < 100; j++) {
        // Two address differs only in diff_bit
        get_random_bytes(&random, 8);
        random >>= (64 - LAT_LENGTH);
        v_addr = basis + random;
        v_addr_1 = v_addr | mask;
        v_addr_0 = v_addr & ~(mask);
        
        preempt_disable();
        
        // Barrier
        asm volatile("DSB 0XF");
        asm volatile("ISB");

        // Cycle Counter1 t1
        asm volatile("MRS %0, PMCCNTR_EL0":"=r" (t1));
			  for (i = 0; i < 1000; ++i) {
          // Load
          asm volatile("ldr %[d], [%[a]]"::[d] "r" (temp), [a] "r" (v_addr_0));
          asm volatile("ldr %[d], [%[a]]"::[d] "r" (temp), [a] "r" (v_addr_1));
          // Clear by VA
	        asm volatile("DC CIVAC, %0"::"r" (v_addr_0));
	        asm volatile("DC CIVAC, %0"::"r" (v_addr_1));
          
          // Barier
          asm volatile("DSB 0XF");
          asm volatile("ISB");
        }
        // Cycle Counter 2 t2
        asm volatile("MRS %0, PMCCNTR_EL0":"=r" (t2));
        
        preempt_enable();
        
        sum += (t2 - t1);
      }
      sum /= 100000;
      printk("L(%2u, %2u): %u \t",diff_bit, diff_bit2, sum);
    }
    printk("\n");
  }
  return 0;
}

void
module_end(void)
{
  printk(KERN_INFO "Remove module \n");
}

module_init(module_bgn);
module_exit(module_end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VandySec Group");
MODULE_DESCRIPTION("Two-bit latency on ARMv8");
MODULE_VERSION("0.01");

