# Modify Refresh Interval
Used for AML-S905X-CC only

Modify the least significant 16 bits of register 0x24 to change DRAM refresh ]
rate
* bits 0~7  t<sub>100ns</sub>
* bits 8~15 t<sub>REFI</sub>
* Increasing these two values can increase refresh interval, making bits easier
  to be flipped. Note: This modification is only used for find relatively 
  vulnerable bits and the refresh rate should not be modified while doing the
  evaluations

