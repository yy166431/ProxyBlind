# Makefile - build ProxyBlind.dylib
TARGET  ?= iphoneos
ARCHS   ?= arm64
SDKROOT ?= $(shell xcrun --sdk $(TARGET) --show-sdk-path 2>/dev/null)
CC      ?= $(shell xcrun --sdk $(TARGET) -f clang)

CFLAGS  = -fPIC -O2 -Wall -Wno-unused-function -Wno-objc-method-access \
          -isysroot $(SDKROOT) -miphoneos-version-min=12.0 -arch $(ARCHS) -fobjc-arc
LDFLAGS = -dynamiclib -isysroot $(SDKROOT) -arch $(ARCHS) \
          -framework Foundation -framework Security

OBJS = ProxyBlind.o fishhook.o

all: ProxyBlind.dylib

ProxyBlind.o: ProxyBlind.m
	$(CC) $(CFLAGS) -c $< -o $@

fishhook.o: fishhook.c fishhook.h
	$(CC) $(CFLAGS) -c fishhook.c -o $@

ProxyBlind.dylib: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) ProxyBlind.dylib
