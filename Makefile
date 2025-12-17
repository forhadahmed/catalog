# Makefile for catalog - high-performance log tokenizer
# Target: 3GB in <2 seconds

CXX := g++
CXXFLAGS := -std=c++17 -O3 -march=native -mtune=native -flto -ffast-math
CXXFLAGS += -funroll-loops -fomit-frame-pointer -finline-functions
CXXFLAGS += -DNDEBUG
LDFLAGS := -pthread -flto

# Debug/test flags
DEBUG_CXXFLAGS := -std=c++17 -g -O0 -fsanitize=address,undefined
DEBUG_LDFLAGS := -pthread -fsanitize=address,undefined

# Profile-guided optimization support
PGO_GEN_FLAGS := -fprofile-generate
PGO_USE_FLAGS := -fprofile-use -fprofile-correction

# Directories
SRC_DIR := src
BIN_DIR := bin
TEST_DIR := test

TARGET := $(BIN_DIR)/catalog
TEST_TARGET := $(BIN_DIR)/catalog_test
TEMPLATE_TEST_TARGET := $(BIN_DIR)/template_test
SOURCES := $(SRC_DIR)/catalog.cc $(SRC_DIR)/template.cc
HEADERS := $(SRC_DIR)/common.h $(SRC_DIR)/template.h
TEST_SOURCES := $(TEST_DIR)/catalog_test.cc
TEMPLATE_TEST_SOURCES := $(TEST_DIR)/template_test.cc

.PHONY: all clean bench pgo debug test test-unit test-integration dirs help

# Default target
all: dirs $(TARGET)

# Help - list all targets
help:
	@echo "Catalog Makefile targets:"
	@echo ""
	@echo "  make / make all    Build optimized binary"
	@echo "  make debug         Build with debug symbols and sanitizers"
	@echo "  make test          Run all tests (unit + integration)"
	@echo "  make test-unit     Run unit tests only"
	@echo "  make test-integration  Run integration tests only"
	@echo "  make bench         Run benchmarks on test files"
	@echo "  make pgo           Profile-guided optimization build"
	@echo "  make clean         Remove build artifacts"
	@echo "  make help          Show this help message"
	@echo ""
	@echo "Usage after build:"
	@echo "  ./bin/catalog [options] encode <input> <output>"
	@echo "  ./bin/catalog [options] decode <input> <output>"
	@echo "  ./bin/catalog [options] bench <input>"
	@echo "  ./bin/catalog [options] tokenize <input>"
	@echo ""
	@echo "Options:"
	@echo "  -t, --threads <n>   Number of threads"
	@echo "  -e, --estimate <n>  Estimated unique tokens"

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(SOURCES) $(HEADERS) | dirs
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -I$(SRC_DIR) -o $@ $(SOURCES)

# Debug build with symbols and sanitizers
debug: CXXFLAGS := $(DEBUG_CXXFLAGS)
debug: LDFLAGS := $(DEBUG_LDFLAGS)
debug: dirs $(TARGET)

# Build test binary
$(TEST_TARGET): $(TEST_SOURCES) | dirs
	$(CXX) $(DEBUG_CXXFLAGS) $(DEBUG_LDFLAGS) -o $@ $<

# Build template test binary
$(TEMPLATE_TEST_TARGET): $(TEMPLATE_TEST_SOURCES) $(HEADERS) | dirs
	$(CXX) $(DEBUG_CXXFLAGS) $(DEBUG_LDFLAGS) -I$(SRC_DIR) -o $@ $<

# Run unit tests
test-unit: $(TEST_TARGET) $(TEMPLATE_TEST_TARGET)
	@echo "=== Running Unit Tests ==="
	./$(TEST_TARGET)
	@echo ""
	@echo "=== Running Template Unit Tests ==="
	./$(TEMPLATE_TEST_TARGET)

# Run integration tests
test-integration: $(TARGET)
	@echo "=== Running Integration Tests ==="
	@chmod +x $(TEST_DIR)/integration_test.sh
	@$(TEST_DIR)/integration_test.sh $(TARGET)

# Run all tests
test: test-unit test-integration
	@echo ""
	@echo "=== All Tests Complete ==="

# Profile-guided optimization (2-phase build for maximum speed)
pgo: clean dirs
	@echo "=== PGO Phase 1: Generating profile ==="
	$(CXX) $(CXXFLAGS) $(PGO_GEN_FLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES)
	./$(TARGET) bench /tmp/large_real.log || true
	@echo "=== PGO Phase 2: Using profile ==="
	$(CXX) $(CXXFLAGS) $(PGO_USE_FLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES)
	rm -f *.gcda

# Quick benchmark
bench: $(TARGET)
	@echo "=== Benchmarking large_real.log (563MB) ==="
	./$(TARGET) bench /tmp/large_real.log
	@echo ""
	@echo "=== Benchmarking 3GB file ==="
	./$(TARGET) bench /tmp/bench_3gb.log

clean:
	rm -rf $(BIN_DIR) *.gcda *.gcno *.o
	rm -f /tmp/catalog_test_*
