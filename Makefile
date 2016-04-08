CFLAGS := -Wall -Werror -lelf -lcapstone -std=c99 -fPIC -O2 -shared

phook.so: phook.o
	gcc phook.o -o phook.so $(CFLAGS)
default: phook.so
clean:
	rm -rf phook.so phook.o
.PHONY: default clean
