**Describir la ejecución de la prueba**
---

### 0. Pasos previos (descargar las herramientas)

Before we begin, make sure you have the following installed on your system:

- A C++ compiler (such as GCC or Clang)
- LLVM (version 10 or later)
- LibFuzzer (included with LLVM)

```bash
sudo apt-get update
sudo apt-get install llvm clang
```

Para comprobar que version de llvm y clang está instalada:

```bash
clang++ --version
llvm-config --version
```

Ahora hay que clonar el repositorio que queremos probar

```bash
sudo mkdir -p /http-libfuzzer
cd ~/http-libfuzzer

git clone https://github.com/thinger-io/IOTMP-Linux.git
```

- ¿¿Es necesario compilar primero el código (o hacer la build) del programa objetivo, con o sin instrumentación, para instalar dependencias o lo que sea??

---

### 1. Crear un “harness” (small fuzzing program - target)

Función → `LLVMFuzzerTestOneInput` 

Con este fragmento de código podemos detectar qué método de /http parsea cadenas/buffers:

```bash
cd ~/http-libfuzzer/IOTMP-Linux
grep -RInE "class .*http_|struct .*http_|parse\s*\(|from_string\s*\(|deserialize\s*\(" src/thinger/http
```

Con eso, vemos en qué clase está el parser.

Con ese grep ya tenemos dos dianas claras y cómodas para empezar el fuzzing de HTTP:

- **`http_cookie::parse(const std::string&)`** → súper sencillo de enganchar (ideal para validar el setup).
- **`http_response_factory::parse(InputIterator begin, end, bool head_request=false)`** → parser “de verdad” que se usa en el cliente (requiere más fuentes al enlazar).

- ***HARNESS 1 → `http_cookie::parse` (Sirve como prueba)***
    - `~/http-libfuzzer/fuzz_http_cookie.cpp`:
        
        ```cpp
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
        ```
        
    - Compílalo directamente (sin CMake, para ir rápido), el parser de cookie suele tener pocas dependencias:
        
        ```bash
        # Instalar dependencias externas necesarias
        sudo apt-get update
        sudo apt-get install libboost-all-dev
        ```
        
        ```bash
        cd ~/http-libfuzzer
        INC="-I$HOME/http-libfuzzer/IOTMP-Linux/src"
        
        clang++ -std=c++17 -O1 -g \
          -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
          $INC \
          IOTMP-Linux/src/thinger/http/http_cookie.cpp \
          fuzz_http_cookie.cpp \
          -o fuzz_http_cookie \
          -lboost_regex
        ```
        
    - Corpus mínimo y diccionario:
        
        ```bash
        mkdir -p corpus_cookie out
        cat > corpus_cookie/basic.txt <<'EOF'
        sessionId=abc123; Path=/; HttpOnly
        EOF
        
        cat > corpus_cookie/attrs.txt <<'EOF'
        name=value; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax
        EOF
        
        cat > corpus_cookie/weird.txt <<'EOF'
        ;=; ;foo=; ;=bar; secure; HTTPONLY; samesite=none
        EOF
        ```
        
    - (Opcional) Diccionario simple:
        
        ```bash
        cat > corpus_cookie/http_cookie.dict <<'EOF'
        "Expires=" "Max-Age=" "Domain=" "Path=" "Secure" "HttpOnly" "SameSite=" "Lax" "Strict" "None" "=" ";" ","
        EOF
        ```
        
    - Ejecutar el fuzzing:
        
        ```bash
        ./fuzz_http_cookie \
        	-timeout=5 \
        	-max_total_time=600 \
        	-rss_limit_mb=1024 \
          -artifact_prefix=out_cookie_fuzzing/ \
          -dict=corpus_cookie/http_cookie.dict \
          corpus_cookie \
          -print_final_stats=1 | tee out_cookie/run.log
        ```
        
        - `./out_cookie` — ejecutable del fuzzer con tu harness de cookies.
        - `timeout=5` — si una sola prueba tarda >5 s, se considera **timeout** y se guarda un *reproducer*.
        - `rss_limit_mb=4096` — mata el proceso si supera ~4 GB de RAM para detectar **OOM**.
            - **OOM = Out Of Memory** → “quedarse sin memoria”.
            - Cuando el fuzzer genera un input que hace que tu programa consuma más memoria de la que le permites (`-rss_limit_mb=4096`), LibFuzzer lo detecta como fallo y guarda un *reproducer* (`oom-xxxx`).
            - Igual de interesante que un crash: indica que cierta entrada puede hacer que el servidor agote memoria.
        - `artifact_prefix=out/` — carpeta **donde guardar** los artefactos (crash-, timeout-, oom-, reduce-, etc.).
        - `dict=corpus_cookie/http_cookie.dict` — **diccionario** de tokens que guían mutaciones (mejor cobertura más rápido).
        - `corpus_cookie` — **directorio de corpus** inicial; también donde **añadirá** nuevos inputs interesantes.
        
        Por defecto **sigue indefinidamente** hasta que:
        
        - Encuentra un **crash/OOM/timeout** → guarda un *reproducer* y **termina** (para seguir pese a crashes: `keep_going=1`).
        - Tú lo paras (`Ctrl+C`).
        - O le pones límite (`runs=N` o `max_total_time=SEG`).
        
        ***RESULTADO:***
        
        ![image.png](attachment:44dc33ad-27dc-436a-99de-a98a592cf916:image.png)
        
    
    Para reproducir un crash: `./fuzz_http_cookie out_cookie_fuzzing/crash-xxxx`
    
    Para seguir encontrando más tras un crash añade: `-keep_going=1`
    
    ***CONCLUSIONES:***
    
    - **Ejecución intensiva**: en 10 minutos, se alcanzaron ~3.7 millones de ejecuciones, con una tasa estable de ~6157 ejec/s. Esto indica que el harness fue eficiente y que el parser no ralentiza al fuzzer.
    - **Cobertura estable**:
        - El número de *coverage features* (`ft`) y de *basic blocks* alcanzados se estabilizó rápidamente (cov: 643, ft: 2085).
        - Esto significa que el parser de cookies tiene un conjunto finito y acotado de rutas de ejecución, que el fuzzer fue capaz de recorrer casi por completo.
    - **Corpus enriquecido**: el corpus inicial se expandió hasta 144 entradas (~24 KB totales), con ~766 nuevas unidades añadidas.
        
        → Es una señal de que libFuzzer logró explorar mutaciones útiles, aunque sin encontrar rutas nuevas después de cierto punto.
        
    - **Consumo de recursos seguro**:
        - Uso máximo de memoria (`peak_rss_mb`) de ~490 MB, muy por debajo del límite fijado (2 GB).
        - No hubo ralentizaciones graves ni *slow units* reportadas.
    - **Ausencia de vulnerabilidades críticas**:
        - No se generaron **crashes**, **OOMs** ni **timeouts** → la implementación de `http_cookie::parse` es robusta frente a entradas aleatorias y malformadas.
        - El parser maneja inputs arbitrarios sin corromper memoria ni colgarse, lo cual es un indicador de solidez.
    - **Diccionario recomendado**: al final se generan tokens recurrentes (secuencias binarias y cadenas cortas), que reflejan qué patrones son relevantes para el parser. Estos pueden servir para futuras sesiones de fuzzing más dirigidas.
    
    ***RESUMEN:***
    
    El fuzzing confirma que **el parser de cookies de Thinger.io es sólido y tolerante a entradas corruptas**, sin vulnerabilidades explotables detectadas en este escenario. Los resultados complementan los obtenidos en la prueba de `http_response_factory`, mostrando consistencia en la calidad de la implementación de HTTP dentro del cliente IoTMP.
    
- ***HARNESS 2 → `http_response_factory***::parse(begin,end,head)` ***(Fuzzing real)***
    
    El método `http_response_factory::parse(begin,end,head)` es plantilla (InputIterator) y devuelve `boost::tribool`. Vamos a darle un buffer `[begin,end)` desde los bytes del fuzzer y compilar junto con las fuentes de HTTP necesarias.
    
    - `~/http-libfuzzer/fuzz_http_response_factory.cpp`
    
    ```cpp
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
    ```

---    

### 2. Compilar el target program

Antes de compilar el fuzzer (harness), es necesario compilar el resto del IOTMP-Linux (con CMake) para compilar las librerías que el harness necesita.

Si enlazamos el harness directamente contra esos `.o` (object files, ficheros intermedios que genera el compilador antes de crear el ejecutable o librería final).

```bash
# Desde ~/http-libfuzzer
mkdir -p build
cd build
```

Instalar todo lo necesario:

```bash
# CMake
sudo apt install cmake

# Dependencias de OpenSSL (headers y libs)
sudo apt-get install libssl-dev pkg-config
```

Lanzar CMake para configurar el proyecto:

```bash
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ../IOTMP-Linux
```

Compilar (genera todos los `.o`):

```bash
cmake --build . -j1
```

Comprobar que existen `.o` de HTTP:

```bash
find . -name '*.o' | grep '/thinger/http/' | head
```

> Hay que hacer una build instrumentada para que los `.o` que utiliza el harness también estén instrumentados. Sino, el fuzzer solo ve cobertura en el harness y no ve las ramas del parser → no crece el corpus como debería.

Sin instrumentación, *libFuzzer* no puede guiarse por cobertura y se queda ciego (solo ve el harness).
> 

Crear un build instrumentado (build a parte para no tocar el que hemos hecho antes):

```bash
cd ~/http-libfuzzer
mkdir -p build_instr
cd build_instr

cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
  -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
  ../IOTMP-Linux

cmake --build . -j1
```

Ahora esos `.o` sí que llevan cobertura (están instrumentados).

Ahora hay que enlazar el harness con ellos (y con el motor del fuzzer).

Instalar otras librerías necesarias para el código:

```bash
# Otras librerías que usa el codigo (spdlog y fmt)
# En el binario normal, CMake las añade automaticamente,
# pero como ahora enlazamos a mano, hay que agregarlas explícitamente
sudo apt-get install libspdlog-dev libfmt-dev
```

Compilar enlazando las fuentes necesarias:

```bash
cd ~/http-libfuzzer
INC="-I$HOME/http-libfuzzer/IOTMP-Linux/src"
BLD="$HOME/http-libfuzzer/build_instr"

# response file con objetos instrumentados
find "$BLD"/CMakeFiles/thinger_iotmp.dir -name '*.o' \
  | grep -E '/thinger/(http|asio|util|data)/' > objs_instr.rsp

# Enlace
clang++ -std=c++17 -O1 -g \
  -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
  $INC \
  "$HOME/http-libfuzzer/fuzz_http_response_factory.cpp" \
  @objs_instr.rsp \
  -o "$HOME/http-libfuzzer/fuzz_http_factory" \
  -lspdlog -lfmt -lboost_regex -lssl -lcrypto -lpthread
```

- `clang++` — Invoca el compilador/enlazador de C++ de LLVM.
- `std=c++17` — Compila el código con estándar C++17.
- `O1` — Nivel de optimización moderado (rápido de compilar, suficiente para fuzzing).
- `g` — Incluye símbolos de depuración (mejor backtraces con ASAN/UBSAN).
- `fsanitize=fuzzer,address,undefined` — Activa el motor de **libFuzzer** y los sanitizadores **ASAN** (memoria) y **UBSAN** (comportamiento indefinido).
- `fno-sanitize-recover=all` — Cuando un sanitizador detecta un bug, **aborta** (no intenta continuar).
- `fno-omit-frame-pointer` — Conserva el frame pointer para backtraces más fiables.
- `$INC` — Ruta(s) de **includes** del proyecto (por ejemplo `I$HOME/http-libfuzzer/IOTMP-Linux/src`).
- `"$HOME/http-libfuzzer/fuzz_http_response_factory.cpp"` — Tu **harness** (define `LLVMFuzzerTestOneInput`).
- `@objs.rsp` — **Response file** con la lista de todos los **.o** del proyecto que necesitas enlazar (http/asio/util/data, etc.). Clang expande ese archivo como si fuesen muchos argumentos.
- `o "$HOME/http-libfuzzer/out_http_factory"` — Nombre del **binario** resultante (el fuzzer).
- `lspdlog -lfmt -lboost_regex -lssl -lcrypto -lpthread` — Bibliotecas a enlazar: logging (`spdlog`, `fmt`), regex de Boost, OpenSSL (`ssl`, `crypto`) y **pthread** para hilos.

---

### 3. Generar seeds (corpus)

Set variado que acelere la cobertura:

```bash
mkdir -p ~/http-libfuzzer/corpus_http

# Respuesta simple con Content-Length
cat > ~/http-libfuzzer/corpus_http/ok_cl.txt <<'EOF'
HTTP/1.1 200 OK
Content-Length: 5

HELLO
EOF

# Chunked encoding
cat > ~/http-libfuzzer/corpus_http/chunked.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked

4
Wiki
5
pedia
0

EOF

# Solo cabeceras, sin cuerpo (204)
cat > ~/http-libfuzzer/corpus_http/no_content.txt <<'EOF'
HTTP/1.1 204 No Content
Date: Wed, 21 Oct 2015 07:28:00 GMT

EOF

# HEAD (sin cuerpo esperado)
cat > ~/http-libfuzzer/corpus_http/head_like.txt <<'EOF'
HTTP/1.1 200 OK
Content-Length: 10

EOF

# Redirección con Location
cat > ~/http-libfuzzer/corpus_http/redirect.txt <<'EOF'
HTTP/1.1 302 Found
Location: https://example.com/

EOF

# Respuesta con gzip (sin cuerpo real, solo para cabeceras)
cat > ~/http-libfuzzer/corpus_http/gzip_header.txt <<'EOF'
HTTP/1.1 200 OK
Content-Encoding: gzip
Content-Length: 20

####################
EOF

# Conexiones
cat > ~/http-libfuzzer/corpus_http/connection_keepalive.txt <<'EOF'
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 1

X
EOF

cat > ~/http-libfuzzer/corpus_http/connection_close.txt <<'EOF'
HTTP/1.1 200 OK
Connection: close
Content-Length: 1

Y
EOF

# Cabeceras duplicadas / múltiples valores
cat > ~/http-libfuzzer/corpus_http/multi_headers.txt <<'EOF'
HTTP/1.1 200 OK
Set-Cookie: a=1; Path=/; HttpOnly
Set-Cookie: b=2; Secure; SameSite=None
Vary: Accept-Encoding, User-Agent
Content-Length: 0

EOF

# Valores raros / Unicode en cabeceras (según aceptación del parser)
cat > ~/http-libfuzzer/corpus_http/unicode_header.txt <<'EOF'
HTTP/1.1 200 OK
X-Emoji: 😺
Content-Length: 0

EOF

# Content-Length inconsistente (semilla "negativa" útil)
cat > ~/http-libfuzzer/corpus_http/bad_content_length.txt <<'EOF'
HTTP/1.1 200 OK
Content-Length: 9999

EOF

# CRLF clásico (libFuzzer puede mutar LFs a CRLFs y viceversa)
cat > ~/http-libfuzzer/corpus_http/crlf.txt <<'EOF'
HTTP/1.1 200 OK\r
Content-Length: 3\r
\r
hey
EOF

# Estado y versión distintos
cat > ~/http-libfuzzer/corpus_http/http_10.txt <<'EOF'
HTTP/1.0 404 Not Found
Content-Length: 9

not found
EOF

# Transfer-Encoding conflictivo con Content-Length
cat > ~/http-libfuzzer/corpus_http/te_vs_cl.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Length: 7

3
foo
0

EOF
```

Añadimos también un pack de seeds retorcidos que ayudan a abrir paths nuevos:

```bash
# CL vs TE conflictivo
cat > ~/http-libfuzzer/corpus_http/te_vs_cl_conflict.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Length: 7

3
foo
0

EOF

# Chunked: tamaño hex inválido
cat > ~/http-libfuzzer/corpus_http/chunked_bad_hex.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked

G
oops
0

EOF

# Chunked: trozo declarado mayor que el cuerpo real
cat > ~/http-libfuzzer/corpus_http/chunked_too_big.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked

A
short
0

EOF

# Chunked: faltan CRLF en fronteras
cat > ~/http-libfuzzer/corpus_http/chunked_missing_crlf.txt <<'EOF'
HTTP/1.1 200 OK
Transfer-Encoding: chunked

4
Wiki5
pedia
0

EOF

# Content-Length duplicado y distinto
cat > ~/http-libfuzzer/corpus_http/dup_content_length.txt <<'EOF'
HTTP/1.1 200 OK
Content-Length: 5
Content-Length: 2

HELLO
EOF

# Cabecera extremadamente larga
cat > ~/http-libfuzzer/corpus_http/very_long_header.txt <<'EOF'
HTTP/1.1 200 OK
X-Long: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Content-Length: 0

EOF

# Cabeceras con espacios raros
cat > ~/http-libfuzzer/corpus_http/weird_spaces.txt <<'EOF'
HTTP/1.1 200 OK
Content-Length : 1
 Connection:    keep-alive

X
EOF

# Line endings mixtos (CRLF/LF)
cat > ~/http-libfuzzer/corpus_http/mixed_line_endings.txt <<'EOF'
HTTP/1.1 200 OK\r
Content-Length: 4\n
\r
test
EOF

# Status/versión fuera de lo normal
cat > ~/http-libfuzzer/corpus_http/weird_status.txt <<'EOF'
HTTP/1.1 999 Weird Status
Content-Length: 0

EOF

# Razón de estado muy larga
cat > ~/http-libfuzzer/corpus_http/long_reason.txt <<'EOF'
HTTP/1.1 200 OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOK
Content-Length: 0

EOF

# Cuerpo binario corto con CL
python3 - <<'PY'
import os, sys, base64, pathlib
p=pathlib.Path(os.path.expanduser('~/http-libfuzzer/corpus_http/bin_body.dat'))
body=b'\x00\xff\x10\x99ABC'
p.write_bytes(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n'%len(body)+body)
print(p)
PY

# Header folding obsoleto (obs-fold)
cat > ~/http-libfuzzer/corpus_http/obs_fold.txt <<'EOF'
HTTP/1.1 200 OK
X-Folded: first
 second
	third
Content-Length: 0

EOF

# Duplicados conflictivos de Connection
cat > ~/http-libfuzzer/corpus_http/dup_connection.txt <<'EOF'
HTTP/1.1 200 OK
Connection: keep-alive
Connection: close
Content-Length: 0

EOF

# Location con caracteres escapables
cat > ~/http-libfuzzer/corpus_http/location_odd.txt <<'EOF'
HTTP/1.1 302 Found
Location: http://exa mple.com/%ZZ
Content-Length: 0

EOF

# Content-Encoding inconsistente con el cuerpo (no gzip real)
cat > ~/http-libfuzzer/corpus_http/fake_gzip.txt <<'EOF'
HTTP/1.1 200 OK
Content-Encoding: gzip
Content-Length: 2

OK
EOF
```

Un diccionario para ayudar a LibFuzzer con tokens HTTP comunes

```bash
cat > ~/http-libfuzzer/corpus_http/http.dict <<'EOF'
"HTTP/1.1" "HTTP/1.0" "200" "204" "301" "302" "400" "404" "500"
"Content-Length:" "Transfer-Encoding:" "chunked" "Connection:" "keep-alive" "close"
"Content-Encoding:" "gzip" "deflate" "br"
"Location:" "Set-Cookie:" "Vary:" "Date:"
"\x0d\x0a" "\x0a\x0a"
EOF
```

---

### 4. Ejecutar el fuzzing

Ejecutar el fuzzer con estas seeds:

```bash
# Crear la carpeta de salida
mkdir -p ~/http-libfuzzer/out_http_fuzzing
```

```bash
cd ~/http-libfuzzer

./fuzz_http_factory \
  -timeout=5 \
  -max_total_time=900 \
  -rss_limit_mb=2048 \
  -artifact_prefix=out_http_fuzzing/ \
  -dict=corpus_http/http.dict \
  -max_len=8192 \
  -use_value_profile=1 \
  -fork=1 -ignore_crashes=1 \
  -jobs=1 -workers=1 \
  -ignore_timeouts=1 -ignore_ooms=1 \
  corpus_http
```

```bash
cd ~/http-libfuzzer
./fuzz_http_factory \
  -timeout=5 \
  -max_total_time=900 \
  -rss_limit_mb=2048 \
  -artifact_prefix=out_http_fuzzing/ \
  -dict=corpus_http/http.dict \
  -use_value_profile=1 \
  -max_len=8192 \
  corpus_http \
  -print_final_stats=1 | tee -a out_http_fuzzing/run.log
```

- `./fuzz_http_factory` — tu binario del fuzzer.
- `timeout=5` — si un **input** tarda >5 s, se trata como timeout (y se guarda un repro).
- `max_total_time=900` — ejecuta ~**15 minutos** y termina (900 s).
- `rss_limit_mb=2048` — límite de memoria a ~**2 GB** (bueno para una VM de 3.8 GB con ASAN).
- `artifact_prefix=out_http_fuzzing/` — directorio donde se guardan **crash-**, **timeout-**, **oom-**.
- `dict=corpus_http/http.dict` — guía mutaciones con tokens HTTP.
- `fork=1` — ejecuta el fuzzing en **subproceso** (permite ignorar fallos y seguir).
- `ignore_crashes=1` — **no para** cuando haya crashes; sigue fuzzing (guarda artefactos igualmente).
- `-max_len=8192` —  tamaño máximo de los inputs que el fuzzer generará. Permite explorar casos más largos y complejos (headers extensos, cuerpos más grandes) sin disparar el límite de 8 MiB que aplica el parser.
- `use_value_profile=1` — activa el *value profiling*: además de la cobertura de ramas, guía el fuzzer con los valores comparados en condiciones (`==`, `<`, etc.), lo que ayuda a acertar cadenas, números o constantes críticas en el parser.
- `jobs=1 -workers=1` — sin paralelismo extra (ideal para VM modesta).
- `corpus_http` — corpus inicial (también se irá enriqueciendo aquí).
    - `corpus_http | tee out_http_fuzzing/run.log` — guarda el log en un archivo.
- `print_final_stats=1` — al finalizar, imprime estadísticas de cobertura, corpus y ejecución (útil para informes).

> Si también quieres ignorar timeouts/OOM para no aparar → añade `-ignore_timeoouts=1 -ignore_ooms=1`
> 

---

### 5. Dejar correr y inspeccionar errores

***LECTURA DE RESULTADOS:***

- **Instrumentación OK**: al inicio se ven cientos de contadores y al final reporta `cov: ~452, ft: ~4768, corp: ~1059`, lo que indica que el fuzzer **sí está viendo ramas** del parser y **amplía el corpus**.
- **Sin artefactos**: no hay `crash-`, `timeout-` ni `oom-` en `out_http_fuzzing/`. Con **ASAN + UBSAN** activos, esto sugiere que, en el espacio explorado, **no se han disparado corrupciones de memoria ni UB**.
- **Logs de tamaño**: las líneas
    
    ```bash
    [error] the response size exceeds the maximum allowed file size: ... (8388608 max)
    ```
    
    provienen de un **guard-rail del parser** (corte a 8 MiB). No son fallos; son rutas de error controladas. Que aparezcan mucho es normal (las mutaciones inventan `Content-Length` gigantes).
    
- **Progreso razonable** (10 min): `new_units_added: 1258` y `corp: ~1059/418 KB` en tu captura — nada mal para un parser HTTP en una VM con RAM ajustada.
- **Uso de memoria**: `peak_rss_mb ~ 196–527 MB` según runs: dentro de lo esperado con ASAN.

> **Conclusión operativa: con el tiempo y seeds que has usado, no hay crashes ni UB; el parser parece robusto frente a entradas agresivas y casos límite comunes.**
> 

---

### CONCLUSIONES

***INTERPRETACIÓN:***

- Con **ASAN + UBSAN**, la ausencia de artefactos sugiere que el parser **no presenta corrupciones de memoria ni UB** en el espacio explorado por el fuzzer en 10–15 min.
- El límite de 8 MiB actúa como **mecanismo de seguridad esperado**; elevarlo no aporta valor y puede degradar el ensayo (más RAM y menos rutas interesantes).
- El incremento de `cov/ft/corpus` confirma que el fuzzer **exploró nuevas rutas**; la gráfica de logs `NEW/REDUCE` y el tamaño del corpus lo respaldan.

***LIMITACIONES:***

- Ensayo focalizado en **respuestas HTTP**; no se ha fuzzeado aún **peticiones** (`http_request`) ni capas superiores (cliente/conexión).
- Duración total **moderada** (10–15 min); sesiones más largas suelen descubrir más rutas en parsers.
- Se usó un único diccionario (HTTP simple); el “recommended.dict” se omitió por parseos estrictos de libFuzzer.

***CONCLUSIÓN:***

En las condiciones probadas (LLVM 19.1.7, ASAN/UBSAN, seeds variadas, 10–15 min), la implementación HTTP de **thinger.io** para respuestas **se comportó de forma robusta**, sin evidenciar **crashes**, **timeouts** ni **OOMs** inducidos por entradas adversarias. Los guard-rails de tamaño actuaron correctamente y se observó **ampliación significativa del corpus** y la cobertura.
