
CC      = gcc
CFLAGS  = -O2 -Wall -DMG_TLS=MG_TLS_OPENSSL -DMG_MAX_RECV_SIZE='(100UL*1024UL*1024UL)'
LIBS    = -lssl -lcrypto
TARGET  = mCollector
SRCS    = mCollector.c nameresolver.c mongoose.c
HDRS    = mongoose.h nameresolver.h mdns.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean

