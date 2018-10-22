# Disable cache maitenance instructions 
Bit 26 of SCTLR_EL1 controls enable/disable of cache maintenance instructions

Bit 14 of SCTLR_EL1 controls enable/disable of DC ZVA instruction

Every time the kernel module will modify system control register in one core.
Use execute.sh to install and remove the kernel module 100 times to ensure 
These instructions are disabled in all cores.

