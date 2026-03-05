#pragma once

// Header to load the std::filesystem namespace (or something compatible with it) as the `fs`
// namespace.  For older compilers (which generally just means macos before pre-10.15) we can't
// actually use std::filesystem because Apple's libc++ developers are incompetent.
//
// Also provides fs::ifstream/ofstream/fstream which will be either directly
// std::ifstream/ofstream/fstream (if under a proper C++17), or a simple wrapper around them that
// supports a C++17-style fs::path filename argument.

#include <string_view>

#ifndef USE_GHC_FILESYSTEM

#include <filesystem>
namespace fs {
  using namespace std::filesystem;
  using ifstream = std::ifstream;
  using ofstream = std::ofstream;
  using fstream = std::fstream;
}
#else

#include <ghc/filesystem.hpp>
namespace fs = ghc::filesystem;

#endif

namespace tools {

// Replaces fs::u8path() — converts UTF-8 std::string/string_view → fs::path (C++20 safe, all platforms)
inline fs::path utf8_path(std::string_view p) {
    return fs::path{std::u8string_view{reinterpret_cast<const char8_t*>(p.data()), p.size()}};
}

// Replaces path.u8string() — converts fs::path → UTF-8 std::string (C++20 safe, all platforms)
inline std::string path_to_str(const fs::path& p) {
    auto u8 = p.u8string();
    return {reinterpret_cast<const char*>(u8.data()), u8.size()};
}

} // namespace tools