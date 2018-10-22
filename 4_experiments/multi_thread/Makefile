FNAME = rowhammer_instr_cmp
ROUNDS = 500

all : 
	gcc multi_thread.c -lrowhammer -pthread

run :
	sudo ./a.out
clean :
	rm a.out

