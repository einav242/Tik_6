
sniffing: sniffing.o 
	gcc -o sniffing sniffing.o -lpcap

sniffing.o: sniffing.c  headers.h
	gcc  -c sniffing.c

task2_1c: task2_1c.o headers.h
	gcc -o task2_1c task2_1c.o -lpcap

task2_1c.o: task2_1c.c 
	gcc  -c task2_1c.c

spoofing:spoofing.o 
	gcc -o spoofing spoofing.o -lpcap

spoofing.o: spoofing.c headers.h
	gcc  -c spoofing.c

task2_3:task2_3.o
	gcc -o task2_3 task2_3.o -lpcap

task2_3.o: task2_3.c headers.h
	gcc  -c task2_3.c


.PHONY: clean
	
clean:
	rm -f *.o  sniffing task2_1c spoofing task2_3