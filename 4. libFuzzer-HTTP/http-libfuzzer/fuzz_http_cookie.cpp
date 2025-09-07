#include <cstdint>
#include <cstddef>
#include <string>
#include "thinger/http/http_cookie.hpp"

// Fuzz target: thinger::http::http_cookie::parse(std::string)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    std::string s(reinterpret_cast<const char*>(data), size);
    auto c = thinger::http::http_cookie::parse(s);
    (void)c; // tocar algo para que no optimice
  } catch (...) {
    // Si el parser lanza, trágatelo: el fuzzer persigue crashes/ubsan/asan
  }
  return 0;
}
