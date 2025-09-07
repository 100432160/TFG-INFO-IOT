#include "thinger/iotmp/core/pson.h"
#include <cstdlib>

namespace protoson {
  // Implementación mínima sobre malloc/free:
  class harness_allocator : public memory_allocator {
  public:
    void* allocate(size_t size) override { return std::malloc(size); }
    void  deallocate(void* p)   override { std::free(p); }
  };

  static harness_allocator g_pool_impl;
  memory_allocator& pool = g_pool_impl;  // define el símbolo global
}
