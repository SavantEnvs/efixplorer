// Known-answer tests for efiXloader's PE / TE / firmware loaders, run by mayhem/test.sh.
// Replays the committed seeds and compares what the loader produced (segments, entry point,
// relocated bytes, extracted modules) with oracle/expected.txt. Built with normal flags.
#include "harness_common.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>

#include "../loader/uefitool.h"

namespace {

int g_pass = 0, g_fail = 0;

void report(const std::string &name, const std::vector<std::string> &errors) {
  if (errors.empty()) {
    printf("PASS %s\n", name.c_str());
    g_pass++;
  } else {
    printf("FAIL %s\n", name.c_str());
    for (const auto &e : errors) {
      printf("  %s\n", e.c_str());
    }
    g_fail++;
  }
}

std::vector<uint8_t> read_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), {});
}

std::string hex(uint64_t v) {
  char b[32];
  snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
  return b;
}

std::vector<std::string> split(const std::string &line) {
  std::istringstream is(line);
  return std::vector<std::string>(std::istream_iterator<std::string>(is), {});
}

void expect(std::vector<std::string> &errs, bool ok, const std::string &msg) {
  if (!ok) {
    errs.push_back(msg);
  }
}

// Checks the recorded segments/entry/memory against the block's `seg`/`entry`/`mem` lines.
void check_image(std::vector<std::string> &errs, const std::vector<std::vector<std::string>> &lines) {
  std::vector<std::vector<std::string>> segs;
  for (const auto &l : lines) {
    if (l[0] == "seg") {
      segs.push_back(l);
    }
  }
  const auto &got = mock::segments();
  expect(errs, got.size() == segs.size(),
         "segment count " + std::to_string(got.size()) + " != " + std::to_string(segs.size()));
  for (size_t i = 0; i < segs.size() && i < got.size(); i++) {
    const auto &e = segs[i];
    bool ok = got[i].name == e[1] && hex(got[i].start) == e[2] && hex(got[i].end) == e[3] &&
              (e.size() < 5 || std::to_string(got[i].perm) == e[4]);
    expect(errs, ok,
           "segment " + std::to_string(i) + ": got " + got[i].name + " " + hex(got[i].start) + "-" +
               hex(got[i].end) + " perm " + std::to_string(got[i].perm) + ", want " + e[1] + " " + e[2] +
               "-" + e[3]);
  }
  for (const auto &l : lines) {
    if (l[0] == "entry") {
      const auto &ents = mock::entries();
      bool ok = ents.size() == 1 && hex(ents[0].ea) == l[1] && hex(ents[0].ord) == l[1] && ents[0].name == l[2];
      expect(errs, ok,
             "entry: got " + std::to_string(ents.size()) + " entries" +
                 (ents.empty() ? "" : " first " + hex(ents[0].ea) + " " + ents[0].name) + ", want " + l[1] +
                 " " + l[2]);
    } else if (l[0] == "mem") {
      uint64_t ea = strtoull(l[1].c_str(), nullptr, 0);
      int width = atoi(l[2].c_str());
      uint64_t want = strtoull(l[3].c_str(), nullptr, 0);
      uint64_t have = mock::peek(ea, width);
      expect(errs, mock::loaded(ea) && have == want,
             "mem[" + l[1] + "]/" + l[2] + ": got " + hex(have) + ", want " + l[3]);
    }
  }
}

void run_image_block(const std::string &root, const std::vector<std::vector<std::string>> &lines) {
  const auto &head = lines[0];
  const std::string &path = head[1];
  bool is_te = head[0] == "te";
  uint16_t machine = uint16_t(strtoul(head[2].substr(head[2].find('=') + 1).c_str(), nullptr, 16));
  auto data = read_file(root + "/" + path);
  std::vector<std::string> errs;
  expect(errs, !data.empty(), "cannot read " + path);
  mock::reset(harness::scratch_dir());
  bool ok = is_te ? harness::load_te(data.data(), data.size(), machine)
                  : harness::load_pe(data.data(), data.size(), machine);
  expect(errs, ok, "loader rejected a valid image");
  check_image(errs, lines);
  report((is_te ? "te:" : "pe:") + path, errs);
}

void run_firmware_block(const std::string &root, const std::vector<std::vector<std::string>> &lines) {
  const std::string &path = lines[0][1];
  auto data = read_file(root + "/" + path);
  std::vector<std::string> errs;
  expect(errs, !data.empty(), "cannot read " + path);

  const std::string &dir = harness::scratch_dir();
  std::filesystem::remove_all(dir + "/firmware.bin.efiloader");
  mock::reset(dir);
  bytevec_t image;
  image.resize(data.size());
  memcpy(image.begin(), data.data(), data.size());
  efiloader::Uefitool uefi(image);
  uefi.dump();
  uefi.dump_jsons();

  size_t nfiles = 0;
  for (const auto &l : lines) {
    if (l[0] == "nfiles") {
      nfiles = size_t(atoi(l[1].c_str()));
    }
  }
  expect(errs, uefi.files.size() == nfiles,
         "module count " + std::to_string(uefi.files.size()) + " != " + std::to_string(nfiles));
  size_t idx = 0;
  for (const auto &l : lines) {
    if (l[0] == "machine") {
      expect(errs, hex(uefi.machine_type) == l[1], "machine type " + hex(uefi.machine_type) + " != " + l[1]);
    } else if (l[0] == "file") {
      if (idx >= uefi.files.size()) {
        errs.push_back("missing module " + l[2]);
        continue;
      }
      const auto &f = uefi.files[idx++];
      std::string guid = f->module_guid.c_str();
      std::transform(guid.begin(), guid.end(), guid.begin(), ::toupper);
      expect(errs, guid == l[1] && std::string(f->module_name.c_str()) == l[2] &&
                       (l[3] == "pe" ? f->is_pe && !f->is_te : f->is_te && !f->is_pe),
             "module " + std::to_string(idx - 1) + ": got " + f->module_guid.c_str() + " " +
                 f->module_name.c_str() + " pe=" + std::to_string(f->is_pe) + " te=" + std::to_string(f->is_te) +
                 ", want " + l[1] + " " + l[2] + " " + l[3]);
    } else if (l[0] == "dump") {
      std::error_code ec;
      auto sz = std::filesystem::file_size(dir + "/firmware.bin.efiloader/" + l[1], ec);
      expect(errs, !ec && sz == uintmax_t(atoll(l[2].c_str())),
             "dumped " + l[1] + " has " + std::to_string(ec ? -1 : (long long)sz) + " bytes, want " + l[2]);
    }
  }

  // the dumped 64-bit PE must load through PeManager like load_file() does
  efiloader::PeManager mgr(uefi.machine_type, false);
  int loaded = 0;
  for (size_t i = 0; i < uefi.files.size(); i++) {
    const auto &f = uefi.files[i];
    if (f->is_pe) {
      const auto *img = reinterpret_cast<const uint8_t *>(f->ubytes.constData());
      loaded += mgr.process(mock::open_buffer(img, f->ubytes.size()), f->module_name.c_str(), int(i)) ? 1 : 0;
    }
  }
  expect(errs, loaded == 1 && mock::segments().size() == 3 && mock::entries().size() == 1,
         "firmware PE load: " + std::to_string(loaded) + " images, " + std::to_string(mock::segments().size()) +
             " segments");
  report("fw:" + path, errs);
}

void run_negative(const std::string &root) {
  {
    std::vector<std::string> errs;
    auto pe64 = read_file(root + "/fuzz_pe/testsuite/amd64.efi");
    auto pe32 = read_file(root + "/fuzz_pe/testsuite/i386.efi");
    mock::reset(harness::scratch_dir());
    expect(errs, !harness::load_pe(pe64.data(), pe64.size(), I386), "64-bit PE accepted in 32-bit mode");
    expect(errs, mock::segments().empty(), "rejected PE still created segments");
    expect(errs, !harness::load_pe(pe32.data(), pe32.size(), AMD64), "32-bit PE accepted in 64-bit mode");
    report("pe:mode-mismatch-rejected", errs);
  }
  {
    std::vector<std::string> errs;
    auto te = read_file(root + "/fuzz_te/testsuite/amd64.te");
    te[0] = 'X';
    mock::reset(harness::scratch_dir());
    expect(errs, !harness::load_te(te.data(), te.size(), AMD64), "TE with a bad signature was accepted");
    expect(errs, mock::segments().empty() && mock::entries().empty(), "rejected TE left segments/entries");
    report("te:bad-signature-rejected", errs);
  }
  {
    std::vector<std::string> errs;
    auto te = read_file(root + "/fuzz_te/testsuite/amd64.te");
    te.resize(60);
    mock::reset(harness::scratch_dir());
    expect(errs, !harness::load_te(te.data(), te.size(), AMD64), "TE with truncated section table was accepted");
    report("te:truncated-rejected", errs);
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <mayhem-dir>\n", argv[0]);
    return 2;
  }
  std::string root = argv[1];
  std::ifstream in(root + "/oracle/expected.txt");
  if (!in) {
    fprintf(stderr, "cannot open expected.txt\n");
    return 2;
  }
  std::vector<std::vector<std::string>> block;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) {
      continue;
    }
    if (line == "end") {
      if (block[0][0] == "fw") {
        run_firmware_block(root, block);
      } else {
        run_image_block(root, block);
      }
      block.clear();
    } else {
      block.push_back(split(line));
    }
  }
  run_negative(root);
  printf("SELFTEST passed=%d failed=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
