# Builds the efiXloader harnesses and selftest. Driven by mayhem/build.sh (flags come from its environment).
# The loader sources are compiled unmodified against the real IDA SDK headers; ida_mock.cc stands in for libida.

SRC      ?= $(abspath ..)
OUT      ?= $(SRC)/build
CC       ?= clang
CXX      ?= clang++
SAN      ?=
DBG      ?= -g -gdwarf-3
# per-build extra compile flags (e.g. -fsanitize=fuzzer-no-link, -O2)
EXTRA    ?=
OBJDIR   ?= $(OUT)/obj

SDK      := $(SRC)/third_party/idasdk/src/include
UT       := $(SRC)/third_party/uefitool
DEFS     := -D__EA64__ -D__LINUX__ -D__IDP__ -DUSE_DANGEROUS_FUNCTIONS -DUSE_STANDARD_FILE_FUNCTIONS \
            -DU_ENABLE_NVRAM_PARSING_SUPPORT -DU_ENABLE_ME_PARSING_SUPPORT -DU_ENABLE_FIT_PARSING_SUPPORT \
            -DU_ENABLE_GUID_DATABASE_SUPPORT
INCS     := -isystem $(SDK) -isystem $(SRC)/third_party -I$(UT)
WARN     := -w
COMMON   := $(SAN) $(DBG) $(EXTRA) $(DEFS) $(INCS) $(WARN) -fPIC
CFLAGS   := $(COMMON)
CXXFLAGS := $(COMMON) -std=c++17

UT_C := $(wildcard $(UT)/common/*.c) $(wildcard $(UT)/common/brotli/common/*.c) \
        $(wildcard $(UT)/common/brotli/dec/*.c) $(wildcard $(UT)/common/bstrlib/*.c) \
        $(UT)/common/digest/sha1.c $(UT)/common/digest/sha256.c $(UT)/common/digest/sha512.c \
        $(UT)/common/digest/sm3.c $(wildcard $(UT)/common/LZMA/*.c) $(wildcard $(UT)/common/LZMA/SDK/C/*.c) \
        $(wildcard $(UT)/common/Tiano/*.c) $(wildcard $(UT)/common/zlib/*.c)
UT_CXX := $(wildcard $(UT)/common/*.cpp) $(wildcard $(UT)/common/bstrlib/*.cpp) \
          $(wildcard $(UT)/common/generated/*.cpp) $(wildcard $(UT)/common/kaitai/*.cpp) \
          $(UT)/UEFIExtract/ffsdumper.cpp $(UT)/UEFIExtract/uefidump.cpp
LDR_CXX := $(SRC)/loader/pe.cc $(SRC)/loader/te.cc $(SRC)/loader/pe_manager.cc $(SRC)/loader/uefitool.cc \
           $(SRC)/mayhem/ida_mock.cc

LIB_OBJS := $(patsubst $(SRC)/%,$(OBJDIR)/%.o,$(UT_C) $(UT_CXX) $(LDR_CXX))

all: $(OUT)/libefixloader.a

$(OUT)/libefixloader.a: $(LIB_OBJS)
	@mkdir -p $(dir $@)
	rm -f $@
	ar rcs $@ $^

$(OBJDIR)/%.c.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJDIR)/%.cpp.o: $(SRC)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(OBJDIR)/%.cc.o: $(SRC)/%.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(LIB_OBJS:.o=.d)
