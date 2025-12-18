# Makefile for catalog - high-performance log tokenizer

CXX := g++
CXXFLAGS := -std=c++17 -O3 -march=native -mtune=native -flto -ffast-math
CXXFLAGS += -funroll-loops -fomit-frame-pointer -finline-functions
CXXFLAGS += -DNDEBUG
LDFLAGS := -pthread -flto

# Debug/test flags
DEBUG_CXXFLAGS := -std=c++17 -g -O0 -fsanitize=address,undefined
DEBUG_LDFLAGS := -pthread -fsanitize=address,undefined

# Directories
SRC_DIR := src
BIN_DIR := bin
TEST_DIR := test

TARGET := $(BIN_DIR)/catalog
TEST_TARGET := $(BIN_DIR)/catalog_test
TEMPLATE_TEST_TARGET := $(BIN_DIR)/template_test
SOURCES := $(SRC_DIR)/catalog.cc $(SRC_DIR)/template.cc
HEADERS := $(SRC_DIR)/mmap.h $(SRC_DIR)/token.h $(SRC_DIR)/template.h $(SRC_DIR)/catalog.h
TEST_SOURCES := $(TEST_DIR)/catalog_test.cc
TEMPLATE_TEST_SOURCES := $(TEST_DIR)/template_test.cc

.PHONY: all clean bench debug test dirs help

# Default target
all: dirs $(TARGET)

# Help - list all targets
help:
	@echo "Targets: all debug test bench clean"

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(SOURCES) $(HEADERS) | dirs
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -I$(SRC_DIR) -o $@ $(SOURCES)

# Debug build with symbols and sanitizers
debug: CXXFLAGS := $(DEBUG_CXXFLAGS)
debug: LDFLAGS := $(DEBUG_LDFLAGS)
debug: dirs $(TARGET)

# Build test binaries
$(TEST_TARGET): $(TEST_SOURCES) $(SOURCES) $(HEADERS) | dirs
	$(CXX) $(DEBUG_CXXFLAGS) $(DEBUG_LDFLAGS) -I$(SRC_DIR) -o $@ $(TEST_SOURCES) $(SRC_DIR)/template.cc

$(TEMPLATE_TEST_TARGET): $(TEMPLATE_TEST_SOURCES) $(SOURCES) $(HEADERS) | dirs
	$(CXX) $(DEBUG_CXXFLAGS) $(DEBUG_LDFLAGS) -I$(SRC_DIR) -o $@ $(TEMPLATE_TEST_SOURCES) $(SRC_DIR)/template.cc

# Run all tests
test: $(TEST_TARGET) $(TEMPLATE_TEST_TARGET) $(TARGET)
	@echo "=== Running Catalog Tests ==="
	./$(TEST_TARGET)
	@echo ""
	@echo "=== Running Template Tests ==="
	./$(TEMPLATE_TEST_TARGET)
	@echo ""
	@echo "=== Running Integration Tests ==="
	@chmod +x $(TEST_DIR)/integration_test.sh
	@$(TEST_DIR)/integration_test.sh $(TARGET)
	@echo ""
	@echo "=== All Tests Complete ==="

# Quick benchmark
bench: $(TARGET)
	@if [ -f /tmp/large_real.log ]; then \
		echo "=== Benchmarking large_real.log ===" && \
		./$(TARGET) bench templates /tmp/large_real.log; \
	elif [ -f /tmp/ribout.log ]; then \
		echo "=== Benchmarking ribout.log ===" && \
		./$(TARGET) bench templates /tmp/ribout.log; \
	else \
		echo "No benchmark file found. Create /tmp/ribout.log or /tmp/large_real.log"; \
	fi

clean:
	rm -rf $(BIN_DIR) *.gcda *.gcno *.o
	rm -f /tmp/catalog_test_*
