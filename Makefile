LDLIBS=-lpcap
CFLAGS=-g

all: send-arp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -o send-arp main.o arphdr.o ethhdr.o ip.o mac.o -lpcap

arphdr.o: arphdr.cpp arphdr.h
	g++ -c -o arphdr.o arphdr.cpp -g

ethhdr.o: ethhdr.cpp ethhdr.h
	g++ -c -o ethhdr.o ethhdr.cpp -g

ip.o: ip.cpp ip.h
	g++ -c -o ip.o ip.cpp -g

mac.o: mac.cpp mac.h
	g++ -c -o mac.o mac.cpp -g 

main.o: main.cpp ethhdr.h arphdr.h
	g++ -c -o main.o main.cpp -g

clean:
	rm -f send-arp *.o
