// LeakSanitizer is off at build time: the loader hands segment_t objects to IDA, which owns them.
extern "C" int __lsan_is_turned_off() { return 1; }
