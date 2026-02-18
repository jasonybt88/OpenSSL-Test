# Makefile for OpenSSL Libraries

CC = gcc
CFLAGS = -Wall -Wextra -I.
LDFLAGS = -lcrypto

TARGET = main
SRCS = custom_algo.c encrypt.c main.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	cmd /c "del /Q $(OBJS) $(TARGET).exe $(TARGET) 2>NUL"
