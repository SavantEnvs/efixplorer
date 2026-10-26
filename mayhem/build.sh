#!/usr/bin/env bash
#
# mayhem/build.sh — builds the efiXloader fuzz harnesses (sanitized, one libFuzzer binary + one
# standalone reproducer per target) and the known-answer selftest (normal flags) that test.sh runs.
#
# efiXloader is the IDA loader half of efiXplorer. It is compiled UNMODIFIED against the real, public
# IDA SDK headers (third_party/idasdk) and the UEFITool submodule; libida (closed source) is replaced by
# mayhem/ida_mock.cc, an in-memory database that implements the kernel entry points the loader calls.
# Fully offline: everything it needs is a submodule or committed here.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
TARGETS="fuzz_pe fuzz_te fuzz_firmware"

for need in third_party/idasdk/src/include/pro.h third_party/uefitool/common/ffsparser.cpp \
            third_party/nlohmann_json/json.hpp; do
  [ -f "$need" ] || { echo "missing $need — submodules not checked out (git submodule update --init --recursive)" >&2; exit 1; }
done

# 1) The loader + UEFITool + mock as a sanitized, SanCov-instrumented library.
make -C mayhem -j"$MAYHEM_JOBS" SRC="$SRC" OUT="$SRC/build/fuzz" CC="$CC" CXX="$CXX" \
     SAN="$SANITIZER_FLAGS" DBG="$DEBUG_FLAGS" EXTRA="-fsanitize=fuzzer-no-link -O1"

# 2) Harnesses: libFuzzer binary + standalone run-once reproducer for each.
CXXFLAGS_H="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -std=c++17 -fPIC -D__EA64__ -D__LINUX__ -D__IDP__ \
 -DUSE_DANGEROUS_FUNCTIONS -DUSE_STANDARD_FILE_FUNCTIONS -isystem $SRC/third_party/idasdk/src/include \
 -isystem $SRC/third_party -I$SRC/third_party/uefitool"
LIB="$SRC/build/fuzz/libefixloader.a"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build/fuzz/standalone_main.o"
$CXX $CXXFLAGS_H -c mayhem/lsan_off.cc -o "$SRC/build/fuzz/lsan_off.o"
for t in $TARGETS; do
  $CXX $CXXFLAGS_H $LIB_FUZZING_ENGINE "mayhem/$t.cc" "$SRC/build/fuzz/lsan_off.o" "$LIB" -o "$SRC/$t"
  $CXX $CXXFLAGS_H "mayhem/$t.cc" "$SRC/build/fuzz/standalone_main.o" "$SRC/build/fuzz/lsan_off.o" "$LIB" \
       -o "$SRC/$t-standalone"
done

# 3) Known-answer selftest: same sources, normal flags (no sanitizers, no SanCov), independent build.
make -C mayhem -j"$MAYHEM_JOBS" SRC="$SRC" OUT="$SRC/build/tests" CC="$CC" CXX="$CXX" \
     SAN="" DBG="" EXTRA="-O1 $COVERAGE_FLAGS"
$CXX -O1 -w -std=c++17 $COVERAGE_FLAGS -D__EA64__ -D__LINUX__ -D__IDP__ -DUSE_DANGEROUS_FUNCTIONS \
     -DUSE_STANDARD_FILE_FUNCTIONS -isystem "$SRC/third_party/idasdk/src/include" -isystem "$SRC/third_party" \
     -I"$SRC/third_party/uefitool" mayhem/selftest.cc "$SRC/build/tests/libefixloader.a" \
     $COVERAGE_FLAGS -o "$SRC/build/tests/selftest"

echo "build.sh: ok"
