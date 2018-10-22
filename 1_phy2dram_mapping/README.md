# Reverse engineering address mapping
* This mapping is done using kernel module
* Use methods provided in **One Bit Flip, One Cloud Flops: Cross-VM Row Hammer
  Attacks and Privilege Escalation** by Yuan Xiao et al.

* The output shows the time needed to access two physical addresses with 
  two bits different (latency).
  * The output has the form L(i,j): T, meaning when two addresses are different
    in bit i and bit j, the access time is T. (if i=j, they have only one
    different bit.
  * Only when two addresses are in different rows of the same bank, the latency
    is large, we can use this feature to identify the row, column, bank bits.
  * The mapping on ARM is relatively simpler than on x86. This is enough for us
    to find the lowest row bit

