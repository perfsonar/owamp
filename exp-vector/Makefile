CFLAGS=-Wall -O2 -DTRACE_KAT_MCT=1

vector: rijndael-api-ref.o rijndael-alg-ref.o vector.c
	gcc $(CFLAGS) -o vector rijndael-api-ref.o rijndael-alg-ref.o vector.c
clean:
	rm -rf vector rijndael-api-ref.o rijndael-alg-ref.o
