// A system GoogleTest that was built without ASan trips libc++'s container-overflow annotations
// (a false positive inside gtest itself). All other ASan checks stay enabled.
extern "C" const char *__asan_default_options() { return "detect_container_overflow=0"; }
