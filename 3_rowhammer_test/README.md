# Find Vulnerable Bits
* This code is used to search for vulnerable bits by hammering:
  1. Address pairs given in an input file
  2. Address pairs found in a large address pool
* The input(if available) and output has the same format
  * Aggressor_phys_addr1 aggressor_phys_addr2 initial_bit
    * Contains the physical addresses of two aggressor rows.
    * If the initial_bit is 0, 0_to_1 bit flip can occur in the victim row
    * If the initial_bit is 1, 1_to_0 bit flip can occur in the victim row
  * The output can be used as input in ../final_experients/ directory
    * Use make send FNAME=(FILENAME) to copy the output to the input directories
    * Specify the name to be stored as FILENAME
