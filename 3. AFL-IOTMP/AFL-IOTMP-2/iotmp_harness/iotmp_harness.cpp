#include <cstdint>
#include <vector>
#include <unistd.h>
#include <cstdio>

#include "thinger/iotmp/core/iotmp_io.hpp"
#include "thinger/iotmp/core/iotmp_decoder.hpp"
#include "thinger/iotmp/core/iotmp_message.hpp"

using namespace thinger::iotmp;

static bool read_all(std::vector<uint8_t>& buf){
  constexpr size_t MAX = 2u << 20; // 2 MiB
  buf.clear();
  uint8_t tmp[4096];
  size_t tot=0; ssize_t n;
  while((n=read(STDIN_FILENO, tmp, sizeof(tmp)))>0){
    if(tot + (size_t)n > MAX) break;
    buf.insert(buf.end(), tmp, tmp+n);
    tot += (size_t)n;
  }
  return !buf.empty();
}

static bool read_varint32(const uint8_t* d, size_t len, size_t& off, uint32_t& out){
  out = 0; int shift = 0;
  while(off < len && shift < 35){
    uint8_t b = d[off++];
    out |= (uint32_t)(b & 0x7F) << shift;
    if((b & 0x80) == 0) return true;
    shift += 7;
  }
  return false;
}

int main(){
  std::vector<uint8_t> in;
  if(!read_all(in)) return 0;

  size_t off = 0;
  uint32_t type_u32 = 0, size = 0;

  if(!read_varint32(in.data(), in.size(), off, type_u32)) return 0;
  if(!read_varint32(in.data(), in.size(), off, size)) return 0;

  // NEW: tope lógico para el body (2 MiB)
  constexpr uint32_t MAX_BODY = 2u << 20; // 2 MiB
  if(size > MAX_BODY) return 0;

  // Check original: que el body quepa en el buffer
  if(size > in.size() - off) return 0;

  uint8_t* body = in.data() + off;

  // Construye el mensaje con el tipo leído
  iotmp_message msg(static_cast<message::type>(type_u32));

  // Decodifica el body con el decoder en memoria
  iotmp_memory_decoder dec(body, size);
  bool ok = dec.decode(msg, size);

  // Evitar optimización
  if(!ok && size==0xFFFFFFFFu) fprintf(stderr, "never\n");
  return 0;
}
