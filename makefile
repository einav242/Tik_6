
sniff: sniffing.o 
	gcc -o sniff sniffing.o -lpcap

sniffing.o: sniffing.c 
	gcc  -c sniffing.c

task2_1c: task2_1c.o 
	gcc -o task2_1c task2_1c.o -lpcap

task2_1c.o: task2_1c.c
	gcc  -c task2_1c.c

spoofing:spoofing.o 
	gcc -o spoofing spoofing.o -lpcap

spoofing.o: spoofing.c
	gcc  -c spoofing.c


.PHONY: clean
	
clean:
	rm -f *.o  sniff task2_1c spoofing