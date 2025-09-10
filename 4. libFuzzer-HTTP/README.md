## Sobre libFuzzer

*LibFuzzer* es una herramienta de *fuzzing* desarrollada dentro del proyecto LLVM y pensada principalmente para programas en C y C++. Al igual que la herramienta anterior, ésta también se adopta el enfoque de *fuzzing* basado en cobertura de código, por lo que va adaptando sus entradas en función de qué partes del programa ha conseguido alcanzar. Su funcionamiento se basa en generar datos de entrada, observar qué rutas de código activa, y a partir de ahí producir nuevas mutaciones que permitan explorar caminos distintos.

Una de las principales ventajas de *libFuzzer* es su integración con los *sanitizers* de LLVM, como *AddressSanitizer* o *UndefinedBehaviorSanitizer*. Gracias a ellos, no solo detecta si el programa se bloquea, sino también problemas de memoria más sutiles como desbordamientos, lecturas fuera de límites, accesos a punteros inválidos o fugas de memoria. Esta característica la convierte en una herramienta muy potente para descubrir errores que podrían pasar desapercibidos con pruebas de *fuzzing* tradicionales.

Aunque sus autores han dejado de trabajar en ella y ya no incorporará nuevas funcionalidades, libFuzzer sigue siendo ampliamente utilizado por su sencillez, buena integración con el ecosistema LLVM y efectividad demostrada en proyectos importantes. De hecho, esta herramienta ha sido utilizada para encontrar vulnerabilidades en software crítico como OpenSSL o el propio kernel de Linux.

LibFuzzer es una alternativa más ligera de AFL++, ambas comparten el enfoque basado en cobertura, pero esta, es más sencilla de utilizar y está especialmente indicada para experimentos iniciales o pruebas rápidas. En este trabajo, se empleará para evaluar la implementación de HTTP en Thinger.io.

---

### Documentación interesante sobre el *code-coverage fuzzing* y libFuzzer

[libFuzzer – a library for coverage-guided fuzz testing. — LLVM 22.0.0git documentation](https://llvm.org/docs/LibFuzzer.html)

[Fuzzing with libFuzzer](https://www.darkrelay.com/post/fuzzing-with-libfuzzer)

[](https://aviii.hashnode.dev/the-art-of-fuzzing-a-step-by-step-guide-to-coverage-guided-fuzzing-with-libfuzzer)

[libFuzzer](https://appsec.guide/docs/fuzzing/c-cpp/libfuzzer/)

[Fuzz con libFuzzer  |  Android Open Source Project](https://source.android.com/docs/security/test/libfuzzer?hl=es-419)

---

### Repositorio con el código fuente que analiza mensajes HTTP

[IOTMP-Linux/src/thinger/http at master · thinger-io/IOTMP-Linux](https://github.com/thinger-io/IOTMP-Linux/tree/master/src/thinger/http)

---

## Pasos para realizar la prueba:

### 0. Pasos previos

Instalar las herramientas que vamos a utilizar: clang y libFuzzer (dentro del paquete de LLVM).

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

### 1. **Crear un punto de entrada al código que queremos probar (“HARNESS”)**

Con este fragmento de código podemos detectar qué método de /http parsea cadenas/buffers:

```bash
cd ~/http-libfuzzer/IOTMP-Linux
grep -RInE "class .*http_|struct .*http_|parse\s*\(|from_string\s*\(|deserialize\s*\(" src/thinger/http
```

Con eso, vemos en qué clase está el parser.

Con ese grep ya tenemos dos funciones diana claras y cómodas para hacer el fuzzing de HTTP:

- **`http_cookie::parse(const std::string&)`** → parser de las cookies HTTP
- **`http_response_factory::parse(InputIterator begin, end, bool head_request=false)`** → parser de los mensajes HTTP comunes

Vamos a probar la robustez de la implementación de ambos parsers, por lo que necesitamos dos harness diferentes:

- ***HARNESS 1 →  Prueba del parsing de cookies***
    - ***Función objetivo → `http_cookie::parse`***
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
        
- ***HARNESS 2 → Prueba del parsing de mensajes HTTP***
    
    ***Función objetivo → `http_response_factory***::parse(begin,end,head)`
    
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
    

### 2. Compilar el target program

Debemos compilar el código fuente y ambos harness para añadir la instrumentación:

- ***HARNESS 1 →  Prueba del parsing de cookies***
    
    Este puede compilarse directamente (sin hacer la build con CMake del código fuente antes), ya que el parser de cookies suele tener pocas dependencias:
    
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
    
- ***HARNESS 2 → Prueba del parsing de mensajes HTTP***
    
    Instalar las dependencias necesarias:
    
    ```bash
    # CMake
    sudo apt install cmake
    
    # Dependencias de OpenSSL (headers y libs)
    sudo apt-get install libssl-dev pkg-config
    ```
    
    En este caso sí que es necesario compilar el resto del IOTMP-Linux (con CMake) para instrumentar las librerías que el harness necesita.
    
    > Hay que hacer una build instrumentada para que los `.o` que utiliza el harness también estén instrumentados. Sino, el fuzzer solo ve cobertura en el harness y no ve las ramas del parser → no crece el corpus como debería.
    
    Sin instrumentación en las dependencias, *libFuzzer* no puede guiarse por cobertura y se queda “ciego” (solo ve el harness).
    > 
    
    Creamos un build instrumentado:
    
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
    
    Instalamos más librerías necesarias para el código:
    
    ```bash
    # Otras librerías que usa el codigo (spdlog y fmt)
    # En el binario normal, CMake las añade automaticamente,
    # pero como ahora enlazamos a mano, hay que agregarlas explícitamente
    sudo apt-get install libspdlog-dev libfmt-dev
    ```
    
    Compilamos enlazando las fuentes necesarias:
    
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
    

### 3. Crear semillas de arranque (seeds para el corpus)

En este caso creamos diferentes sets de semillas para las distintas pruebas, ya que sus estructuras son diferentes:

- ***HARNESS 1 →  Prueba del parsing de cookies***
    - Corpus mínimo:
        
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
        
    - Creamos también un diccionario simple con tokens comunes:
        
        ```bash
        cat > corpus_cookie/http_cookie.dict <<'EOF'
        "Expires=" "Max-Age=" "Domain=" "Path=" "Secure" "HttpOnly" "SameSite=" "Lax" "Strict" "None" "=" ";" ","
        EOF
        ```
        
- ***HARNESS 2 → Prueba del parsing de mensajes HTTP***
    - Set variado que acelere la cobertura:
    
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
    
    - Añadimos también un pack de seeds retorcidos que ayudan a abrir paths nuevos:
    
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
    
    - Un diccionario para ayudar a LibFuzzer con tokens HTTP comunes
    
    ```bash
    cat > ~/http-libfuzzer/corpus_http/http.dict <<'EOF'
    "HTTP/1.1" "HTTP/1.0" "200" "204" "301" "302" "400" "404" "500"
    "Content-Length:" "Transfer-Encoding:" "chunked" "Connection:" "keep-alive" "close"
    "Content-Encoding:" "gzip" "deflate" "br"
    "Location:" "Set-Cookie:" "Vary:" "Date:"
    "\x0d\x0a" "\x0a\x0a"
    EOF
    ```
    

### 4. Ejecutar el fuzzing

Ya podemos ejecutar el fuzzing para las dos pruebas:

- ***HARNESS 1 →  Prueba del parsing de cookies***
    
    ```bash
    # Crear la carpeta de salida
    mkdir -p ~/http-libfuzzer/out_cookie_fuzzing
    ```
    
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
    
    > Para reproducir un crash: `./fuzz_http_cookie out_cookie_fuzzing/crash-xxxx`
    > 
    
- ***HARNESS 2 → Prueba del parsing de mensajes HTTP***
    
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

### 5. Dejar correr y inspeccionar errores

- ***HARNESS 1 →  Prueba del parsing de cookies***
    
    <img width="1071" height="855" alt="Image" src="https://github.com/user-attachments/assets/c5a94138-9c6a-4c91-889f-5f861195095a" />
    
    1. El *fuzzer* muestra signos de que se ha expandido: aumenta la cobertura (*coverage features, ft*; y *coverage counters, cov*) y el directorio de corpus se llena de nuevos casos de prueba generados por el *libFuzzer*.
    2. El uso máximo de memoria es de ~490 MB, muy por debajo del límite fijado.
    3. No se generan *crashes*, *OOMs* (fallos de memoria), ni *timeouts* en el directorio de salida, lo que indica que no ha habido fallos durante la ejecución.
    
- ***HARNESS 2 → Prueba del parsing de mensajes HTTP***
    
    <img width="948" height="126" alt="Image" src="https://github.com/user-attachments/assets/103265e5-689a-4796-9480-7eafa6b1a0cf" />

  <img width="1082" height="878" alt="Image" src="https://github.com/user-attachments/assets/022fcc58-5920-4cf9-97e7-b658d38f6f87" />
    
    1. La cobertura se expande (se muestra en métricas del *log* de la terminal como *cov* o *ft*, y en los nuevos casos de *test* que se generan en el directorio del *corpus*).
    2. Aparece un error en los *logs* de la terminal:[error] the response size exceeds the maximum allowed file size: ... (8388608 max)
        
        Sin embargo, esto no es un fallo, es una ruta de error controlada por el *parser* que controla que el tamaño de los mensajes entrantes.
        
    3. No se generan artefactos (*crashes*, *timeouts*, ni *OOMs*) en el directorio de salida, lo que se traduce en que no se han producido fallos.

### 6. Conclusiones

Los resultados del *fuzzing* sobre la implementación HTTP de Thinger.io han sido muy positivos. Tanto en el *parser* de *cookies* como en el de mensajes HTTP, *libFuzzer* fue capaz de recorrer un conjunto amplio de rutas de código sin provocar fallos. No se registraron *crashes*, *timeouts* ni problemas de memoria, lo que indica que el sistema es capaz de manejar entradas corruptas o aleatorias sin comprometer su estabilidad. El único “error” detectado en las pruebas no corresponde a una vulnerabilidad real, sino a un mecanismo de seguridad que corta las respuestas cuando superan los 8 MB de tamaño, evitando así un uso excesivo de memoria o intentos de abuso.

Estos resultados sugieren que la implementación de HTTP en Thinger.io es robusta frente a entradas malformadas. Aunque siempre podrían aparecer casos más complejos en campañas más largas o con configuraciones distintas, las pruebas realizadas muestran que, al menos en condiciones realistas, el protocolo se comporta de manera sólida y predecible.
