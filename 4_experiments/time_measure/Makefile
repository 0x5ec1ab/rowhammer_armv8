all : 
	gcc time_measure.c -lrowhammer -pthread

run :
	sudo ./a.out > results
	cat results
clean :
	rm ./a.out
