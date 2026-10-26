// Shared glue for the efiXloader harnesses: drives the unmodified loader classes
// (PeManager / PE / TE / Uefitool) over the in-memory IDA mock.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "ida_mock.h"

#include "../loader/pe_manager.h"
#include "../loader/te.h"

namespace harness {

constexpr size_t kMaxInput = 4u << 20;

inline const std::string &scratch_dir() {
  static const std::string dir = [] {
    const char *base = getenv("TMPDIR");
    std::string tmpl = std::string(base && *base ? base : "/tmp") + "/efix.XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back(0);
    if (!mkdtemp(buf.data())) {
      abort();
    }
    return std::string(buf.data());
  }();
  return dir;
}

inline uint16_t rd16(const uint8_t *p) { return uint16_t(p[0] | (p[1] << 8)); }

// What the real loader does for a PE that IDA would refuse to continue with:
// load_file() dies in PE::good() ("failed to guess PE bitness") when an MZ image
// has an unknown machine word, so such input never reaches the code under test.
// Returns 0 when the image is not an MZ image or not loadable, else the machine.
inline uint16_t pe_machine(const uint8_t *d, size_t n) {
  if (n < 0x40 || rd16(d) != MZ_SIGN) {
    return 0;
  }
  uint64_t off = rd16(d + 0x3c);
  if (off + 6 > n) {
    return 0;
  }
  uint16_t m = rd16(d + off + 4);
  return (m == AMD64 || m == AARCH64 || m == I386) ? m : 0;
}

inline uint16_t te_machine(const uint8_t *d, size_t n) {
  if (n < TE_HEADER_SIZE || rd16(d) != TE_SIGN) {
    return 0;
  }
  return rd16(d + 2);
}

inline uint16_t pecpu_for(uint16_t machine) {
  return machine == AARCH64 ? PECPU_ARM64 : PECPU_AMD64;
}

inline bool load_pe(const uint8_t *d, size_t n, uint16_t machine, int ord = 0) {
  efiloader::PeManager mgr(pecpu_for(machine), machine == I386);
  return mgr.process(mock::open_buffer(d, n), "image.efi", ord);
}

inline bool load_te(const uint8_t *d, size_t n, uint16_t machine, int ord = 0) {
  efiloader::PeManager mgr(pecpu_for(machine), machine == I386);
  return mgr.process_te(mock::open_buffer(d, n), "image.te", ord);
}

} // namespace harness
