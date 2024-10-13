all:
	gcc -o trafpi main.c src/help.c src/snifer.c src/findMonitor.c -lpcap

clean:
	rm -rf *.o main