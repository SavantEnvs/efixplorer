// Host-side stand-in for the IDA kernel (libida) that efiXloader links against.
// The loader sources are compiled unmodified against the real IDA SDK headers; this
// provides the kernel entry points they call, backed by an in-memory database.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <pro.h>
#include <ida.hpp>
#include <diskio.hpp>

namespace mock {

struct Segment {
  uint64_t start, end;
  std::string name, sclass;
  int perm, type, bitness;
};

struct Entry {
  uint64_t ord, ea;
  std::string name;
};

// Drop every segment/entry/byte and reset the inf flags; point get_path() at `dir`.
void reset(const std::string &dir);

// A linput_t over a caller-owned buffer. The loader closes it (close_linput).
linput_t *open_buffer(const uint8_t *data, size_t size);

const std::vector<Segment> &segments();
const std::vector<Entry> &entries();
uint64_t peek(uint64_t ea, int bytes);
bool loaded(uint64_t ea);
uint32_t memory_crc();

} // namespace mock
