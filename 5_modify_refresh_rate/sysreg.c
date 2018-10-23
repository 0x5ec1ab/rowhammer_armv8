/**
  * systemreg -- modify DRAM refresh interval on AML-S905-CC
  * By VandySec Group
**/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>

#define BASE_ADDR 0xC8838000
#define REG_NUM   0x000000FE
#define REG_SIZE  4

int
sysreg_start(void)
{
  int i;
  void __iomem *regPtr;
  unsigned regVal;
  printk(KERN_INFO "Insert module \n");
  
  // map physical addresses of regs to kernel's address space
  regPtr = ioremap(BASE_ADDR, REG_NUM * REG_SIZE);

  
  // reset the refresh interval
  //iowrite32(0x20104C33, regPtr + 0x24 * REG_SIZE);

  // change the refresh interval (least significant 16 bits)
  //iowrite32(0x20104e5D, regPtr + 0x24 * REG_SIZE);

  for (i = 0; i < REG_NUM; i++) {
    regVal = ioread32(regPtr + i * REG_SIZE);
    printk("regVal 0x%04x is 0x%08x\n", i, regVal);
  }
  
  // unmap this address region
  iounmap(regPtr);
  
  return 0;
}

void
sysreg_end(void)
{
  printk(KERN_INFO "Remove module \n");
}

module_init(sysreg_start);
module_exit(sysreg_end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VandySec Group");
MODULE_DESCRIPTION("Modify DRAM refresh interval");
MODULE_VERSION("0.01");

