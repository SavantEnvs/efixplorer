// Fuzz efiXloader's Terse Executable (TE) image loader (efiloader::TE via PeManager::process_te).
#include "harness_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > harness::kMaxInput) {
    return -1;
  }
  uint16_t machine = harness::te_machine(data, size);
  if (!machine) {
    return -1;
  }
  mock::reset(harness::scratch_dir());
  harness::load_te(data, size, machine);
  return 0;
}
