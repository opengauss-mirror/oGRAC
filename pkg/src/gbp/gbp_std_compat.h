#pragma once

// GCC 7 libstdc++ can enable pthread_cond_clockwait while older glibc headers
// do not declare it. Keep std::condition_variable on the portable fallback path.
#if defined(__has_include)
#if __has_include(<bits/c++config.h>)
#include <bits/c++config.h>
#undef _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT
#endif
#elif defined(__GNUC__)
#include <bits/c++config.h>
#undef _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT
#endif
