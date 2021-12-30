
sniff: sniffing.o 
	gcc -o sniff sniffing.o -lpcap

sniffing.o: sniffing.c headers.h
	gcc  -c sniffing.c

# my_mat.o: my_mat.c my_mat.h
# 	gcc -Wall -c my_mat.c

# my_may.so: main.o my_mat.o
# 	gcc -shared -o my_mat.so main.o my_mat.o

# my_mat.a: main.o my_mat.o
# 	ar -rcs my_mat.a main.o my_mat.o

.PHONY: clean all
	
clean:
	rm -f *.o 