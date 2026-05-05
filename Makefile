
CC      = gcc
CFLAGS  = -O2 -Wall -DMG_TLS=MG_TLS_OPENSSL -DMG_MAX_RECV_SIZE='(100UL*1024UL*1024UL)'
LIBS    = -lssl -lcrypto
TARGET  = mCollector
SRCS    = mCollector.c nameresolver.c mongoose.c
HDRS    = mongoose.h nameresolver.h mdns.h embedded_assets.h

all: $(TARGET)

embedded_assets.h: index.html mCollector.ps1
	@echo "Generating embedded_assets.h"
	@( \
	  echo '/* Auto-generated from index.html and mCollector.ps1 — do not edit. */'; \
	  echo '#ifndef EMBEDDED_ASSETS_H'; \
	  echo '#define EMBEDDED_ASSETS_H'; \
	  echo ''; \
	  xxd -i index.html | sed 's/unsigned char/static const unsigned char/;s/unsigned int/static const unsigned int/'; \
	  echo ''; \
	  xxd -i mCollector.ps1 | sed 's/unsigned char/static const unsigned char/;s/unsigned int/static const unsigned int/'; \
	  echo ''; \
	  echo '#endif'; \
	) > $@

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET) embedded_assets.h

.PHONY: all clean
