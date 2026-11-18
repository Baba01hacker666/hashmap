CXX ?= c++
AR ?= ar
PYTHON ?= python3
BUILD ?= build
CXXFLAGS ?= -O3 -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
LDLIBS += -lcrypto

.PHONY: all check bench sanitize clean
all: $(BUILD)/rsm_cpp $(BUILD)/librsm1.a

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: cpp/%.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/librsm1.a: $(BUILD)/rsm.o
	$(AR) rcs $@ $^

$(BUILD)/rsm_cpp: $(BUILD)/main.o $(BUILD)/librsm1.a
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/rsm_test: $(BUILD)/test.o $(BUILD)/librsm1.a
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

check: $(BUILD)/rsm_cpp $(BUILD)/rsm_test
	$(BUILD)/rsm_test
	$(BUILD)/rsm_cpp pack example.json $(BUILD)/sample.rsm
	cmp example.rsm $(BUILD)/sample.rsm
	$(BUILD)/rsm_cpp unpack example.rsm $(BUILD)/sample.json
	cmp example.json $(BUILD)/sample.json

bench: all
	$(PYTHON) bench_cpp.py --exe $(BUILD)/rsm_cpp

sanitize:
	$(MAKE) BUILD=$(BUILD)/sanitize CXXFLAGS='-std=c++20 -O1 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-fsanitize=address,undefined -no-pie' check

clean:
	rm -rf -- $(BUILD)

-include $(wildcard $(BUILD)/*.d)
