CFLAGS := -Wall -Werror -lelf -lcapstone -std=c99 -fPIC -O2 -shared

phook.so: phook.o
default: phook.so
clean:
	rm -rf phook.so phook.o
