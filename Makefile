# libtlv — build, test and fuzz.
#
#   make            build static lib + tests
#   make test       run the unit/consistency suite under ASan+UBSan
#   make fuzz       run libFuzzer for FUZZ_SECONDS (default 600) with
#                   dedup/minimize/triage wired in
#   make corpus     rebuild corpus/regression from the triaged crash set
#
# The default compiler is a clang that ships compiler-rt with -fsanitize=fuzzer.
# Apple's Command Line Tools clang does NOT, so we prefer Homebrew LLVM.

# Homebrew LLVM is required for -fsanitize=fuzzer; Apple's CLT clang lacks it.
ifeq ($(origin CC),default)
CC      := $(shell if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then \
                     echo /opt/homebrew/opt/llvm/bin/clang; else echo clang; fi)
endif
LLVM_BIN ?= $(dir $(CC))
FUZZ_SECONDS ?= 600
SAN        := address,undefined
OPT        := -O1 -g -fno-omit-frame-pointer
WARN       := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
              -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
STD        := -std=c11
DEFS       := -D_GNU_SOURCE
INC        := -Iinclude -Isrc

CFLAGS     := $(STD) $(WARN) $(OPT) $(DEFS) $(INC)
LIB_SRCS   := src/tlv_varint.c src/tlv_arena.c src/tlv_parse.c src/tlv_query.c src/tlv_writer.c

BUILD      := build

.PHONY: all lib test fuzz fuzz-check fuzz-legacy legacy-triage corpus clean \
        triage docs

all: lib
lib: $(BUILD)/libtlv.a

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/libtlv.a: $(LIB_SRCS) include/tlv.h src/tlv_internal.h | $(BUILD)
	@set -e; objs=""; for s in $(LIB_SRCS); do \
	  o=$(BUILD)/$$(basename $$s .c).o; \
	  $(CC) $(CFLAGS) -c $$s -o $$o; \
	  objs="$$objs $$o"; \
	done; \
	$(AR) rcs $@ $$objs
	@echo "built $@ (CC=$(CC))"

# ---- unit tests: compiled with the same sanitizers as the fuzzer ----
$(BUILD)/test_tlv: tests/test_tlv.c $(LIB_SRCS) include/tlv.h src/tlv_internal.h | $(BUILD)
	$(CC) $(STD) $(WARN) $(OPT) -fsanitize=$(SAN) -fno-sanitize-recover=all \
	  $(DEFS) $(INC) tests/test_tlv.c $(LIB_SRCS) -o $@

test: $(BUILD)/test_tlv
	$(BUILD)/test_tlv

# ---- reference fixture: the legacy parser, fuzzed to produce real crashes ----
$(BUILD)/fuzz_legacy: fuzz/fuzz_legacy.c legacy/legacy_tlv.c legacy/legacy_tlv.h | $(BUILD)
	$(CC) $(STD) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,$(SAN) \
	  -fno-sanitize-recover=all -Ilegacy fuzz/fuzz_legacy.c legacy/legacy_tlv.c -o $@

# ---- fuzzer binaries ----
$(BUILD)/fuzz_tlv: fuzz/fuzz_tlv.c $(LIB_SRCS) include/tlv.h src/tlv_internal.h | $(BUILD)
	$(CC) $(STD) $(WARN) $(OPT) -fsanitize=fuzzer,$(SAN) -fno-sanitize-recover=all \
	  $(DEFS) $(INC) fuzz/fuzz_tlv.c $(LIB_SRCS) -o $@

# Fuzz with crash-file management: every artifact is triaged by tools/triage.py,
# which dedups by stack fingerprint, minimizes the sample and files it under
# corpus/regression/<class>/ plus a human-readable report in artifacts/.
FUZZ_JOBS ?= 4

# corpus/seed is read-only input: libFuzzer is given it first, then
# build/corpus as the writable corpus it evolves. Without the separate writable
# dir, libFuzzer drops hundreds of sha-named files into the checked-in seeds.
fuzz: $(BUILD)/fuzz_tlv
	@echo "--- libFuzzer for $(FUZZ_SECONDS)s under ASan+UBSan ---"
	@mkdir -p $(BUILD)/crashes $(BUILD)/corpus
	@cp -n corpus/seed/* $(BUILD)/corpus/ 2>/dev/null || true
	@cp -n corpus/regression/*.tlv $(BUILD)/corpus/ 2>/dev/null || true
	@# -fork runs several independent jobs and -ignore_crashes=1 keeps going
	@# after a crash, so one run collects many artifacts for triage instead of
	@# stopping at the first. Exit status therefore says nothing about crashes;
	@# the triage step below is what decides pass/fail.
	@$(BUILD)/fuzz_tlv -artifact_prefix=$(BUILD)/crashes/ \
	  -max_len=8192 -timeout=10 -dict=fuzz/tlv.dict \
	  -fork=$(FUZZ_JOBS) -ignore_crashes=1 \
	  $(BUILD)/corpus \
	  -print_final_stats=1 -rss_limit_mb=2048 \
	  -max_total_time=$(FUZZ_SECONDS) 2>&1 | tee $(BUILD)/fuzz.log || true
	@python3 tools/triage.py --crashes $(BUILD)/crashes --binary $(BUILD)/fuzz_tlv \
	  --regression corpus/regression --artifacts artifacts
	@echo "--- replaying regression corpus (must be crash-free) ---"
	@$(BUILD)/fuzz_tlv -runs=1 corpus/regression
	@echo "fuzz: no live crashes after $(FUZZ_SECONDS)s"

# Continuous check: crash-free replay plus a short fuzz burst. Used by CI.
fuzz-check: $(BUILD)/fuzz_tlv
	@mkdir -p $(BUILD)/crashes $(BUILD)/corpus
	@$(BUILD)/fuzz_tlv -runs=1 corpus/regression
	@cp -n corpus/seed/* $(BUILD)/corpus/ 2>/dev/null || true
	@$(BUILD)/fuzz_tlv -artifact_prefix=$(BUILD)/crashes/ -max_total_time=60 \
	  -dict=fuzz/tlv.dict $(BUILD)/corpus >/dev/null 2>&1

# Fuzz the legacy fixture and triage what it finds. This is how the crash
# classes in docs/CRASHES.md were produced.
fuzz-legacy: $(BUILD)/fuzz_legacy
	@mkdir -p $(BUILD)/legacy-crashes $(BUILD)/legacy-corpus
	@cp -n corpus/seed/* $(BUILD)/legacy-corpus/ 2>/dev/null || true
	@$(BUILD)/fuzz_legacy -artifact_prefix=$(BUILD)/legacy-crashes/ \
	  -max_len=8192 -timeout=10 -dict=fuzz/tlv.dict \
	  -max_total_time=$(FUZZ_SECONDS) -fork=4 -ignore_crashes=1 \
	  $(BUILD)/legacy-corpus -print_final_stats=1 2>&1 | tee $(BUILD)/fuzz-legacy.log || true
	@python3 tools/triage.py --crashes $(BUILD)/legacy-crashes \
	  --binary $(BUILD)/fuzz_legacy --regression $(BUILD)/legacy-regression \
	  --artifacts $(BUILD)/legacy-artifacts

corpus: $(BUILD)/fuzz_tlv
	@python3 tools/triage.py --crashes $(BUILD)/crashes --binary $(BUILD)/fuzz_tlv \
	  --regression corpus/regression --artifacts artifacts --rebuild-index

docs:
	@echo "docs/PROTOCOL.md, docs/FUZZING.md"

clean:
	rm -rf $(BUILD)
