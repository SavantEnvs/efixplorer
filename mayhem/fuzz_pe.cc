// Fuzz efiXloader's PE/PE32+ image loader (efiloader::PE via PeManager::process).
#include "harness_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > harness::kMaxInput) {
    return -1;
  }
  uint16_t machine = harness::pe_machine(data, size);
  if (!machine) {
    return -1;
  }
  mock::reset(harness::scratch_dir());
  harness::load_pe(data, size, machine);
  return 0;
}
