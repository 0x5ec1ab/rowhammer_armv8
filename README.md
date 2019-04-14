# rowhammer_armv8

The preliminary results are published in our paper "**Triggering Rowhammer Hardware Faults on ARM: A Revisit**".

This code works on board AML-S905X-CC(Le Potato). 
To use it on other boards, some minor modifications may be needed. 

**NOTE:**
As our focus is on how to trigger the rowhammer bug on ARMv8-A platforms, some of the technical challenges like obtaining the physical-to-DRAM address mapping and finding appropriate aggressor rows are solved directly by leveraging some privileged interfaces/methods. 
However, after pairs of aggressor rows are acquired, the hammering process is unprivileged.

# How to run our experiments
### Get mapping from physical address to DRAM

We implement this in a kernel module. 
To perform double-sided hammering, we are interested in the second lowest row bit.
(We found the second lowest row bit is bit 16 of the physical address on AML-S905X-CC.)

```
cd 1_phy2dram_mapping 
make  
make test  
```


### Install pagemap lib

This library can be used to read "/proc/\<pid\>/pagemap" file and find candidate aggressor pairs

```
cd 2_find_aggressors  
make  
make install  
```

### Start rowhammer test

Run rowhammer program and output flippable bits

```
cd 3_rowhammer_test  
make  
make run  
```

Sending output as input of experiments

```
make send
```

### Experiments

  * Experiment 1: Finding relationships between the number of iterations and the number of bit flips

  * Experiment 2: Measuring the execution time of different apporaches

  * Experiment 3: Comparing the effectiveness of different approaches

  * Experiment 4: Measuring the performance of multi-threaded hammering
    - You can also disable cache maintenance instructions

### Modify refresh rate (optional)

  * Applicable on AML-S905X-CC(Le Potato) only

  * Can modify refresh interval of DRAM

  * Only used to quickly find potential aggressor rows
