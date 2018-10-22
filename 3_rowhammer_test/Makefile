FNAME=input0
all : 
	gcc find_vulnerable.c -lrowhammer -pthread

run :
	sudo ./a.out
clean :
	rm ./a.out
send :
	cat results_0_to_1 results_1_to_0 > results
	cp results ../4_experiments/bitflip_iteration/input/$(FNAME)
	cp results ../4_experiments/compare_all_instr/input/$(FNAME)
	cp results ../4_experiments/multi_thread/input/$(FNAME)
