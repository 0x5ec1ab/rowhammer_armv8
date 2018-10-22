/**
  * disable_cachemaint -- disable cache maitenance instructions and DC ZVA
  * By VandySec Group
**/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>

int
disable_cache(void)
{
  unsigned long reg_value = 0;
  printk(KERN_INFO "Disable cache maintenance instructions and DC ZVA\n");
  // check original systemcontrol values
  asm volatile("mrs %0, SCTLR_EL1":"=r" (reg_value));
  printk("SCTLR_EL1 is 0x%lx\n", reg_value);
  // disable cache maintenance instructions
  reg_value &= ~(1 << 26);
  // disable DC ZVA
  reg_value &= ~(1 << 14);
  // write the modified value back to SCTLR_EL1 register
  asm volatile("msr SCTLR_EL1, %0"::"r" (reg_value));
  return 0;
}

void
enable_cache(void)
{
  printk(KERN_INFO "Instructions disabled \n");
}

module_init(disable_cache);
module_exit(enable_cache);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VandySec Group");
MODULE_DESCRIPTION("Disable cache maintenance instructions and DC ZVA");
MODULE_VERSION("0.01");

