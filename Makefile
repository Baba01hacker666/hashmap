# hashmap - multithreaded hash toolkit
#
# MIT License - Copyright (c) 2026 baba01hacker666

CC      ?= cc
MODULES  := util charset crypto bcrypt engine brute digest map search wordlist main
SRCS     := $(MODULES:%=src/%.c)
OBJS     := $(SRCS:.c=.o)
DEPS     := $(OBJS:.o=.d)
BIN      := hashmap

HARD_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror \
               -Wshadow -Wcast-align -Wstrict-prototypes \
               -Wmissing-prototypes -Wundef -Wformat=2 \
               -Wdouble-promotion -Wconversion -Wsign-conversion
OPT_FAST := -O3 -march=native -flto -pthread -D_FORTIFY_SOURCE=2
INC := -Isrc

.PHONY: all clean debug portable test install install-hooks

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OPT_FAST) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(HARD_CFLAGS) $(INC) -O3 -MMD -MP -c $< -o $@

# sanitizer build (exact same strict warnings)
debug: HM_CFLAGS := $(HARD_CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -pthread
debug: $(SRCS)
	$(CC) $(HM_CFLAGS) $(INC) -fPIC -o $(BIN)-debug $(SRCS)

# portable static-ish build for release artifacts (no -march=native/lto)
portable: HM_CFLAGS := $(HARD_CFLAGS) -O2 -fPIE -pthread -static
portable: $(SRCS)
	$(CC) $(HM_CFLAGS) $(INC) -o $(BIN)-portable $(SRCS)

test: $(BIN)
	@./tests/run.sh

# wordlists: fetch the common password lists, dedupe and combine them
#   make wordlist       top lists only (~4.6M candidates, seconds)
#   make wordlist-full  everything incl. RockYou (~34M candidates, ~1 min)
wordlist:
	@./tools/fetch-wordlists.sh --fast

wordlist-full:
	@./tools/fetch-wordlists.sh --full

.PHONY: wordlist wordlist-full

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/hashmap

# enable the co-author guard hooks for this clone
install-hooks:
	@chmod +x .githooks/commit-msg .githooks/prepare-commit-msg
	@git config core.hooksPath .githooks
	@echo "hooks enabled: Co-Authored-By trailers are now blocked"

clean:
	rm -f $(OBJS) $(DEPS) $(BIN) $(BIN)-debug $(BIN)-portable

-include $(DEPS)
