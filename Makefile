all:
	gcc -o main main.c src/help.c src/snifer.c -lpcap

clean:
	rm -rf *.o main