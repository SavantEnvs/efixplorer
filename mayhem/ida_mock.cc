// Host-side stand-in for the IDA kernel (libida): the subset of entry points that
// efiXloader's loader sources call, backed by an in-memory database. See ida_mock.h.
#include "ida_mock.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <unordered_map>

#include <bytes.hpp>
#include <entry.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

class linput_t {
public:
  const uint8_t *data;
  size_t size;
  qoff64_t pos;
};

namespace {

constexpr uint64_t PAGE_BITS = 12;
constexpr size_t PAGE_SIZE_ = size_t(1) << PAGE_BITS;

struct Page {
  uint8_t bytes[PAGE_SIZE_];
  uint8_t loaded[PAGE_SIZE_];
};

struct State {
  std::unordered_map<uint64_t, Page *> pages;
  std::vector<mock::Segment> segments;
  std::vector<mock::Entry> entries;
  std::map<uint64_t, size_t> strlits;
  std::map<uint32_t, size_t> inf;
  std::string dir;
  std::string cmd_path;
  std::string idb_path;
  sel_t next_sel = 1;
};

State g;

Page *page_for(uint64_t ea, bool create) {
  auto it = g.pages.find(ea >> PAGE_BITS);
  if (it != g.pages.end()) {
    return it->second;
  }
  if (!create) {
    return nullptr;
  }
  auto *p = new Page;
  memset(p, 0, sizeof(*p));
  g.pages[ea >> PAGE_BITS] = p;
  return p;
}

void store_byte(uint64_t ea, uint8_t v) {
  Page *p = page_for(ea, true);
  p->bytes[ea & (PAGE_SIZE_ - 1)] = v;
  p->loaded[ea & (PAGE_SIZE_ - 1)] = 1;
}

bool byte_at(uint64_t ea, uint8_t *out) {
  Page *p = page_for(ea, false);
  if (!p || !p->loaded[ea & (PAGE_SIZE_ - 1)]) {
    return false;
  }
  *out = p->bytes[ea & (PAGE_SIZE_ - 1)];
  return true;
}

uint64_t read_le(uint64_t ea, int n) {
  uint64_t v = 0;
  for (int i = 0; i < n; i++) {
    uint8_t b = 0;
    byte_at(ea + i, &b);
    v |= uint64_t(b) << (8 * i);
  }
  return v;
}

void add_le(uint64_t ea, int n, uint64_t delta) {
  if (!mock::loaded(ea)) {
    return;
  }
  uint64_t v = read_le(ea, n) + delta;
  for (int i = 0; i < n; i++) {
    store_byte(ea + i, uint8_t(v >> (8 * i)));
  }
}

[[noreturn]] void host_abort(const char *what) {
  fprintf(stderr, "[ida_mock] the IDA loader session would terminate: %s\n",
          what);
  abort();
}

} // namespace

namespace mock {

void reset(const std::string &dir) {
  for (auto &kv : g.pages) {
    delete kv.second;
  }
  g.pages.clear();
  g.segments.clear();
  g.entries.clear();
  g.strlits.clear();
  g.inf.clear();
  g.next_sel = 1;
  g.dir = dir;
  g.cmd_path = dir + "/firmware.bin";
  g.idb_path = dir + "/firmware.i64";
}

linput_t *open_buffer(const uint8_t *data, size_t size) {
  auto *li = new linput_t;
  li->data = data;
  li->size = size;
  li->pos = 0;
  return li;
}

const std::vector<Segment> &segments() { return g.segments; }
const std::vector<Entry> &entries() { return g.entries; }
uint64_t peek(uint64_t ea, int bytes) { return read_le(ea, bytes); }

bool loaded(uint64_t ea) {
  uint8_t b;
  return byte_at(ea, &b);
}

uint32_t memory_crc() {
  std::map<uint64_t, Page *> sorted(g.pages.begin(), g.pages.end());
  uint32_t crc = 0xFFFFFFFFu;
  for (auto &kv : sorted) {
    for (size_t i = 0; i < PAGE_SIZE_; i++) {
      if (!kv.second->loaded[i]) {
        continue;
      }
      uint64_t ea = (kv.first << PAGE_BITS) + i;
      uint8_t buf[9];
      memcpy(buf, &ea, 8);
      buf[8] = kv.second->bytes[i];
      for (uint8_t c : buf) {
        crc ^= c;
        for (int k = 0; k < 8; k++) {
          crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
        }
      }
    }
  }
  return ~crc;
}

} // namespace mock

// --------------------------------------------------------------------------
// pro.h
void *ida_export qalloc_or_throw(size_t size) {
  void *p = malloc(size ? size : 1);
  if (!p) {
    throw std::bad_alloc();
  }
  return p;
}

void ida_export qfree(void *alloc) { free(alloc); }

void *ida_export qvector_reserve(void *vec, void *old, size_t cnt,
                                 size_t elsize) {
  struct raw_qvector {
    void *array;
    size_t n, alloc;
  };
  auto *v = static_cast<raw_qvector *>(vec);
  if (cnt <= v->alloc) {
    return old;
  }
  size_t grown = v->alloc + v->alloc / 2;
  size_t newalloc = cnt > grown ? cnt : grown;
  void *p = realloc(old, newalloc * elsize);
  if (!p) {
    throw std::bad_alloc();
  }
  v->alloc = newalloc;
  return p;
}

int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...) {
  va_list va;
  va_start(va, format);
  int r = __builtin_vsnprintf(buffer, n, format, va);
  va_end(va);
  return r;
}

uint32 ida_export calc_file_crc32(linput_t *li) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < li->size; i++) {
    crc ^= li->data[i];
    for (int k = 0; k < 8; k++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
    }
  }
  return ~crc;
}

bool ida_export utf16_utf8(qstring *out, const wchar16_t *in, int nsyms) {
  out->clear();
  for (int i = 0; nsyms < 0 || i < nsyms; i++) {
    uint32_t c = in[i];
    if (c == 0 && nsyms < 0) {
      break;
    }
    if (c >= 0xD800 && c < 0xDC00 && (nsyms < 0 || i + 1 < nsyms) &&
        in[i + 1] >= 0xDC00 && in[i + 1] < 0xE000) {
      c = 0x10000 + ((c - 0xD800) << 10) + (in[i + 1] - 0xDC00);
      i++;
    }
    char buf[4];
    int len;
    if (c < 0x80) {
      buf[0] = char(c);
      len = 1;
    } else if (c < 0x800) {
      buf[0] = char(0xC0 | (c >> 6));
      buf[1] = char(0x80 | (c & 0x3F));
      len = 2;
    } else if (c < 0x10000) {
      buf[0] = char(0xE0 | (c >> 12));
      buf[1] = char(0x80 | ((c >> 6) & 0x3F));
      buf[2] = char(0x80 | (c & 0x3F));
      len = 3;
    } else {
      buf[0] = char(0xF0 | (c >> 18));
      buf[1] = char(0x80 | ((c >> 12) & 0x3F));
      buf[2] = char(0x80 | ((c >> 6) & 0x3F));
      buf[3] = char(0x80 | (c & 0x3F));
      len = 4;
    }
    out->append(buf, len);
  }
  return true;
}

// --------------------------------------------------------------------------
// diskio.hpp: loader input source
void ida_export lread(linput_t *li, void *buf, size_t size) {
  // IDA terminates the session on a short read; model the input as zero-padded
  // instead so every reachable state corresponds to a real (padded) file.
  ssize_t got = qlread(li, buf, size);
  if (got < 0) {
    got = 0;
  }
  if (size_t(got) < size) {
    memset(static_cast<uint8_t *>(buf) + got, 0, size - size_t(got));
  }
}

ssize_t ida_export qlread(linput_t *li, void *buf, size_t size) {
  if (li->pos < 0 || size_t(li->pos) >= li->size) {
    return 0;
  }
  size_t n = li->size - size_t(li->pos);
  if (n > size) {
    n = size;
  }
  memcpy(buf, li->data + li->pos, n);
  li->pos += n;
  return ssize_t(n);
}

qoff64_t ida_export qlseek(linput_t *li, qoff64_t pos, int whence) {
  qoff64_t base = 0;
  if (whence == SEEK_CUR) {
    base = li->pos;
  } else if (whence == SEEK_END) {
    base = qoff64_t(li->size);
  }
  if (pos < -base) {
    return -1;
  }
  li->pos = base + pos;
  return li->pos;
}

int64 ida_export qlsize(linput_t *li) { return int64(li->size); }

void ida_export close_linput(linput_t *li) { delete li; }

// --------------------------------------------------------------------------
// loader.hpp
int ida_export file2base(linput_t *li, qoff64_t pos, ea_t ea1, ea_t ea2,
                         int /*patchable*/) {
  if (pos < 0 || size_t(pos) > li->size || ea2 < ea1) {
    return 0;
  }
  uint64_t want = ea2 - ea1;
  uint64_t have = li->size - size_t(pos);
  uint64_t n = want < have ? want : have;
  for (uint64_t i = 0; i < n; i++) {
    store_byte(ea1 + i, li->data[size_t(pos) + i]);
  }
  return 1;
}

void ida_export vloader_failure(const char *format, va_list va) {
  char buf[512];
  __builtin_vsnprintf(buf, sizeof(buf), format ? format : "", va);
  host_abort(buf);
}

const char *ida_export get_path(path_type_t pt) {
  switch (pt) {
  case PATH_TYPE_IDB:
    return g.idb_path.c_str();
  default:
    return g.cmd_path.c_str();
  }
}

// --------------------------------------------------------------------------
// ida.hpp / typeinf.hpp / idp.hpp: database-wide settings
size_t ida_export getinf(inftag_t tag) {
  auto it = g.inf.find(tag);
  return it == g.inf.end() ? 0 : it->second;
}

bool ida_export setinf(inftag_t tag, ssize_t value) {
  g.inf[tag] = size_t(value);
  return true;
}

bool ida_export getinf_flag(inftag_t tag, uint32 mask) {
  return (getinf(tag) & mask) != 0;
}

bool ida_export setinf_flag(inftag_t tag, uint32 mask, bool value) {
  size_t cur = getinf(tag);
  return setinf(tag, ssize_t(value ? (cur | mask) : (cur & ~size_t(mask))));
}

bool ida_export set_compiler(const compiler_info_t &, int, const char *) {
  return true;
}

bool ida_export set_processor_type(const char *, setproc_level_t) {
  return true;
}

// --------------------------------------------------------------------------
// bytes.hpp
uint32 ida_export get_dword(ea_t ea) { return uint32(read_le(ea, 4)); }
uint64 ida_export get_qword(ea_t ea) { return read_le(ea, 8); }
ushort ida_export get_word(ea_t ea) { return ushort(read_le(ea, 2)); }
bool ida_export is_loaded(ea_t ea) { return mock::loaded(ea); }
void ida_export add_word(ea_t ea, uint64 value) { add_le(ea, 2, value); }
void ida_export add_dword(ea_t ea, uint64 value) { add_le(ea, 4, value); }
void ida_export add_qword(ea_t ea, uint64 value) { add_le(ea, 8, value); }

bool ida_export create_data(ea_t, flags64_t, asize_t, tid_t) { return true; }
bool ida_export del_items(ea_t, int, asize_t, may_destroy_cb_t *) {
  return true;
}
bool ida_export set_cmt(ea_t, const char *, bool) { return true; }
bool ida_export set_op_type(ea_t, flags64_t, int) { return true; }

bool ida_export create_strlit(ea_t start, size_t len, int32) {
  g.strlits[start] = len;
  return true;
}

size_t ida_export get_max_strlit_length(ea_t ea, int32, int) {
  size_t limit = 0x1000;
  auto it = g.strlits.find(ea);
  if (it != g.strlits.end()) {
    limit = it->second;
  }
  size_t n = 0;
  uint8_t b;
  while (n < limit && byte_at(ea + n, &b) && b != 0) {
    n++;
  }
  return n;
}

ssize_t ida_export get_strlit_contents(qstring *utf8, ea_t ea, size_t len,
                                       int32, size_t *, int) {
  utf8->clear();
  uint8_t b;
  for (size_t i = 0; i < len && byte_at(ea + i, &b) && b != 0; i++) {
    utf8->append(char(b));
  }
  return ssize_t(utf8->length());
}

// --------------------------------------------------------------------------
// offset.hpp / lines.hpp / entry.hpp / segment.hpp
reftype_t ida_export get_default_reftype(ea_t) { return REF_OFF32; }
bool ida_export op_offset(ea_t, int, uint32, ea_t, ea_t, adiff_t) {
  return true;
}
bool ida_export op_offset_ex(ea_t, int, const refinfo_t *) { return true; }

bool ida_export vadd_extra_line(ea_t, int, const char *format, va_list va) {
  char buf[512];
  __builtin_vsnprintf(buf, sizeof(buf), format, va);
  return true;
}

bool ida_export add_entry(uval_t ord, ea_t ea, const char *name, bool, int) {
  g.entries.push_back({ord, ea, name ? name : ""});
  return true;
}

sel_t ida_export allocate_selector(ea_t) { return g.next_sel++; }

bool ida_export add_segm_ex(segment_t *s, const char *name, const char *sclass,
                            int) {
  if (s->start_ea >= s->end_ea) {
    return false;
  }
  g.segments.push_back({s->start_ea, s->end_ea, name ? name : "",
                        sclass ? sclass : "", int(s->perm), int(s->type),
                        int(s->bitness)});
  return true;
}

// --------------------------------------------------------------------------
// kernwin.hpp: the UI dispatcher. Only msg output is interpreted, and only so
// that the loader's format strings are exercised; it is discarded.
static callui_t mock_callui(ui_notification_t what, ...) {
  callui_t r;
  memset(&r, 0, sizeof(r));
  if (what == ui_msg) {
    va_list ap;
    va_start(ap, what);
    const char *format = va_arg(ap, const char *);
    auto *args = va_arg(ap, __builtin_va_list *);
    va_end(ap);
    char buf[1024];
    r.i = __builtin_vsnprintf(buf, sizeof(buf), format, *args);
  }
  return r;
}

callui_t(idaapi *callui)(ui_notification_t what, ...) = mock_callui;
