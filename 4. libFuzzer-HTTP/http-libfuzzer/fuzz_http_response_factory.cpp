#include <cstdint>
#include <cstddef>
#include <vector>
#include "thinger/http/http_response_factory.hpp"

// Algunos parsers distinguen si la request era HEAD (sin cuerpo). Probamos ambos caminos.
static void feed_once(const uint8_t* data, size_t size, bool head_request) {
  // Usamos vector<char> para iteradores bidireccionales
  std::vector<char> buf(data, data + size);
  thinger::http::http_response_factory factory;
  // La API del factory es templada: parse(begin, end, bool head_request=false)
  try {
    auto r = factory.parse(buf.begin(), buf.end(), head_request);
    (void)r; // boost::tribool
  } catch (...) {
    // swallow
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  feed_once(data, size, false);
  feed_once(data, size, true);
  return 0;
}
