CC=gcc
CFLAG=-O2 -lpcap

make:
	$(CC) $(CFLAG) main.c -o pcap-test
