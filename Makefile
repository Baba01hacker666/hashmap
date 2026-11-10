CC      ?= cc
CFLAGS  ?= -O3 -march=native -mtune=native -flto -funroll-loops \
           -std=c11 -Wall -Wextra -Wpedantic
LDLIBS   = -lpthread -lm
BIN      = hashmap

build: $(BIN)

$(BIN): src/$(BIN).c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# portable build (no -march=native) for release tarballs
portable:
	$(CC) -O3 -flto -funroll-loops -std=c11 -Wall -Wextra -Wpedantic \
		$(LDFLAGS) -o $(BIN) src/$(BIN).c $(LDLIBS)

install: $(BIN)
	install -Dm755 $(BIN) $(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: build portable install clean
