// Fuzz efiXloader's UEFI firmware path: the same sequence as efi_loader.cc load_file() —
// UEFITool parse, module extraction/dump, deps/guids JSON, then PE/TE loading of every
// extracted module — over firmware images given as raw bytes.
#include "harness_common.h"

#include <algorithm>

#include "../loader/uefitool.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char sig[] = "_FVH";
  if (size < 64 || size > harness::kMaxInput ||
      std::search(data, data + size, sig, sig + 4) == data + size) {
    return -1;
  }
  {
    // Uefitool's constructor calls loader_failure() (terminates IDA) when UEFITool rejects the image.
    TreeModel probe_model;
    FfsParser probe(&probe_model);
    if (probe.parse(UByteArray(reinterpret_cast<const char *>(data), uint32_t(size)))) {
      return -1;
    }
  }

  const std::string &dir = harness::scratch_dir();
  std::filesystem::remove_all(dir + "/firmware.bin.efiloader");
  mock::reset(dir);

  bytevec_t image;
  image.resize(size);
  memcpy(image.begin(), data, size);

  efiloader::Uefitool uefi(image);
  if (uefi.messages_occurs()) {
    uefi.show_messages();
  }
  uefi.dump();
  uefi.dump_jsons();

  efiloader::PeManager mgr(uefi.machine_type, false);
  for (size_t i = 0; i < uefi.files.size(); i++) {
    const auto &file = uefi.files[i];
    if (file->is_te) {
      continue;
    }
    if (file->is_pe) {
      const auto *img = reinterpret_cast<const uint8_t *>(file->ubytes.constData());
      size_t len = file->ubytes.size();
      if (harness::pe_machine(img, len) == 0 && len >= 2 && harness::rd16(img) == MZ_SIGN) {
        continue;
      }
      mgr.process(mock::open_buffer(img, len), file->module_name.c_str(), int(i));
    }
  }
  return 0;
}
