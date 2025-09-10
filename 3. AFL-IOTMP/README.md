## Sobre AFL y AFL++

*American Fuzzy Lop (AFL)* es uno de los *fuzzers* más conocidos y utilizados en el mundo de la ciberseguridad. Fue desarrollado originalmente por Michal Zalewski y se convirtió en una referencia por su capacidad para descubrir fallos de seguridad importantes en diferentes tipos de software. La clave de AFL es en su enfoque de *fuzzing* guiado por cobertura: en lugar de limitarse a generar entradas aleatorias, introduce mutaciones sobre los casos base de prueba (*seeds*) y, gracias a la instrumentación del código, mide si se accede a nuevas rutas de ejecución. Esto permite que el *fuzzer* aprenda y evolucione, explorando progresivamente zonas cada vez más profundas del programa que se analiza.

En el *paper* en el que se basa este trabajo se utilizó AFL en su versión original, pero en este caso se ha optado por emplear AFL++ (*AFLPlusPlus*), un *fork* más moderno y activo que incorpora numerosas mejoras. AFL++ es más rápido, tiene más y mejores opciones de mutación e instrumentación, y añade soporte para módulos personalizados. [CITA?]

Una de las principales ventajas de AFL++ y el *fuzzing* basado en cobertura de código es que no necesita que el protocolo esté exhaustivamente documentado para ser eficaz. Mientras que enfoques como el *protocol-aware fuzzing*, que requiere un conocimiento detallado de la estructura de los mensajes, o el *fuzzing* aleatorio, que no es muy eficaz, AFL++ trabaja directamente sobre el código fuente del programa, introduciendo entradas malformadas y observando cómo varía el flujo de ejecución. Esta característica hace que esta herramienta sea especialmente adecuada para protocolos poco documentados o propietarios, como por ejemplo IOTMP.

---

## Repositorios de AFL y AFL++

[GitHub - google/AFL: american fuzzy lop - a security-oriented fuzzer](https://github.com/google/AFL?tab=readme-ov-file)

https://github.com/antonio-morales/Fuzzing101

https://github.com/AFLplusplus/AFLplusplus

https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/README.md

---

## Repositorios de documentación de IOTMP y Thinger.io

https://github.com/thinger-io/Docs

https://github.com/thinger-io/IOTMP

---

## Repositorio con el código fuente que analiza mensajes IOTMP

[GitHub - thinger-io/IOTMP-Linux: IOTMP Client for Linux devices](https://github.com/thinger-io/IOTMP-Linux/tree/master)

---

## Pasos para realizar la prueba:

### 0. Pasos previos

1. Instalar imagen de Docker de AFL++
    
    ```bash
    docker pull aflplusplus/aflplusplus:latest
    ```
    
2. Clonar el repositorio con el código fuente
    
    ```bash
    mkdir -p ~/AFL-IOTMP-2
    cd ~/AFL-IOTMP-2
    git clone https://github.com/thinger-io/IOTMP-Linux.git
    ```
    
3. Lanzar el contenedor montando esa carpeta en ‘/src’. Le damos un nombre para poder volver a abrir el contenedor de nuevo más tarde.
    
    ```bash
    docker run --name afl-iotmp-2 -it \
      -v "$HOME/AFL-IOTMP-2":/src \
      -w /src \
      aflplusplus/aflplusplus:latest bash
    ```
    
    - `docker run` → crea y arranca un nuevo contenedor basado en una imagen.
    - `--name afl-iotmp-2` → asigna un nombre identificativo al contenedor (`afl-iotmp-2`) para poder referirse a él más adelante.
    - `-it` → combina `i` (modo interactivo: mantiene la entrada estándar abierta) y `t` (asigna un pseudo-terminal), lo que permite trabajar con una consola dentro del contenedor.
    - `-v "$HOME/AFL-IOTMP-2":/src` → monta un volumen, enlazando la carpeta local `$HOME/AFL-IOTMP-2` con `/src` dentro del contenedor. Así el código y los resultados se guardan en tu máquina aunque el contenedor se borre.
    - `-w /src` → define el *working directory* (directorio de trabajo) dentro del contenedor al arrancar, en este caso `/src`.
    - `aflplusplus/aflplusplus:latest` → indica la imagen de Docker a utilizar, en este caso la oficial de AFL++ en su versión más reciente (`latest`).
    - `bash` → comando inicial que se ejecuta dentro del contenedor; abre una shell interactiva Bash.
    
    Para reabrir el contenedor creado previamente:
    
    ```bash
    # Para iniciar el contenedor las siguientes veces
    docker start -ai afl-iotmp-2
    ```
    
    - `docker start` → arranca un contenedor que ya ha sido creado previamente (pero que ahora está detenido).
    - `-a` → adjunta la salida del contenedor a la terminal actual (para ver lo que ocurre dentro).
    - `-i` → mantiene la entrada estándar abierta, de forma que se puede interactuar.
    - `afl-iotmp-2` → nombre del contenedor que queremos arrancar (el mismo que definimos con `--name`).
    

### **1. Crear un punto de entrada al código que queremos probar (“HARNESS”):**

Necesitamos un ejecutable (o mini-programa “harness”) que **lea datos por stdin/archivo** y los pase al **parser IoTMP**. Cuanto más pequeño y directo sea, mejor fuzzer saldrá.

- Creamos el `harness` más pequeño posible que haga: lee bytes → decodifica 2 varints (type, size) → llama a `iotmp_memory_decoder.decode(...)` con el body
    - Dentro del contenedor (`/src/iotmp_harness/iotmp_harness.cpp`):
        
        ```bash
        mkdir -p iotmp_harness
        chown -R 1000:1000 /src/iotmp_harness
        ```
        
        ```cpp
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
        ```
        
    - Definir un allocator concreto para `protoson::pool`
        - El protocolo IOTMP utiliza internamente PSON, un formato de datos donde los mensajes se decodifican en forma de objetos, *arrays* o *strings*. Cada vez que el parser crea uno de estos elementos, necesita reservar memoria, y para ello recurre a una capa de asignación llamada `protoson::pool`.
        - Dentro del contenedor (`/src/iotmp_harness/protoson_pool_def.cpp`):
        
        ```cpp
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
        ```
        

### **2. Compilar el código fuente con instrumentación:**

Construimos el código fuente del repositorio `IOTMP-Linux` con los compiladores de AFL++ para instrumentarlo (”sensores” que permiten que el binario sepa a qué ramas entra durante la ejecución). Sin esto, AFL no sabe por dónde va y no puede guiarse en la creación de nuevos inputs.

1. **Antes de compilar, instalar dependencias del sistema dentro del contenedor:**
    
    ```bash
    # 1) Dependencias necesarias
    apt-get update
    apt-get install -y \
    	libssl-dev \
    	pkg-config \
      libboost-system-dev \
      libboost-filesystem-dev \
      libboost-thread-dev \
      libboost-program-options-dev \
      libboost-regex-dev \
      libboost-date-time-dev
      
    # (opcional, para comprobar) 
    openssl version || true
    pkg-config --cflags --libs openssl || true
    ```
    
- **Build con ASAN + AFL del core IoTMP** → esta build dará mejor señal en errores de memoria dentro del core, no solo del harness
    1. Preparar carpetas y compilers de AFL++
        
        ```bash
        cd /src/IOTMP-Linux
        mkdir -p /src/install
        rm -rf build-asan && mkdir build-asan && cd build-asan
        ```
        
    2. Configurar y compilar (CMake → Make)
        
        ```bash
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        
        cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
              -DCMAKE_C_COMPILER="$CC" \
              -DCMAKE_CXX_COMPILER="$CXX" \
              -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O1" \
              -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O1" \
              -DCMAKE_INSTALL_PREFIX=/src/install \
              ..
        make -j"$(nproc)"
        make install
        ```
        
    3. Extraer una librería sólo del core (opcional pero útil)
        - CMake habrá generado `libthinger_iotmp.a`. Creamos **`libiotmp_core.a`** solo con objetos de `thinger/iotmp/core/**` para evitar dependencias innecesarias.
        
        ```bash
        # En el mismo build-asan:
        rm -f libiotmp_core_asan.a
        OBJS=$(find CMakeFiles -type f -name '*.o' | grep '/thinger/iotmp/core/')
        ar rcs libiotmp_core_asan.a $OBJS
        ranlib libiotmp_core_asan.a
        
        # Comprobar que no arrastra spdlog/fmt (debería no salir nada):
        nm -C libiotmp_core_asan.a | egrep -i 'spdlog|fmt::' || echo "OK: sin spdlog/fmt en core (ASAN)"
        
        # Dejar la .a en una ruta estable:
        cp -f libiotmp_core_asan.a /src/IOTMP-Linux/build-asan/libiotmp_core.a
        ```
        
    4. **Compilar el harness y enlazar contra el core:**
        
        ```bash
        mkdir -p /src/install
        
        export CXX=afl-clang-fast++
        
        $CXX -std=c++17 -g -O1 \
          -fsanitize=address -fno-omit-frame-pointer \
          -I/src/IOTMP-Linux/src \
          /src/iotmp_harness/iotmp_harness.cpp \
          /src/iotmp_harness/protoson_pool_def.cpp \
          /src/IOTMP-Linux/build-asan/libiotmp_core.a \
          -lssl -lcrypto -lpthread -ldl \
          -o /src/install/iotmp_harness_dbg
        ```
        
- ***Build sin ASAN + AFL del core IoTMP →*** Esta build sirve para confirmar que hay *crashes* reales sin ASAN (no causados solo por corrupción de memoria)
    1. Preparar carpetas y compilers de AFL++
        
        ```bash
        cd /src/IOTMP-Linux
        rm -rf build-noasan && mkdir build-noasan && cd build-noasan
        ```
        
    2. Configurar y compilar (CMake → Make)
        
        ```bash
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_C_COMPILER="$CC" \
              -DCMAKE_CXX_COMPILER="$CXX" \
              -DCMAKE_INSTALL_PREFIX=/src/install \
              ..
        make -j"$(nproc)"
        make install
        ```
        
    3. Extraer una librería sólo del core (opcional pero útil)
        
        ```bash
        # Librería core “limpia”
        rm -f libiotmp_core_noasan.a
        OBJS=$(find CMakeFiles -type f -name '*.o' | grep '/thinger/iotmp/core/')
        ar rcs libiotmp_core_noasan.a $OBJS
        ranlib libiotmp_core_noasan.a
        
        nm -C libiotmp_core_noasan.a | egrep -i 'spdlog|fmt::' || echo "OK: sin spdlog/fmt en core (NO ASAN)"
        cp -f libiotmp_core_noasan.a /src/IOTMP-Linux/build-noasan/libiotmp_core.a
        ```
        
    4. Compilar el harness sin ASAN:
        
        ```bash
        export CXX=afl-clang-fast++
        
        $CXX -std=c++17 -O2 -g \
          -I/src/IOTMP-Linux/src \
          /src/iotmp_harness/iotmp_harness.cpp \
          /src/iotmp_harness/protoson_pool_def.cpp \
          /src/IOTMP-Linux/build-noasan/libiotmp_core.a \
          -lssl -lcrypto -lpthread -ldl \
          -o /src/install/iotmp_harness_noasan
        ```
        
    

### **3. Crear semillas de arranque (seeds):**

Creamos varias semillas base que ayudarán a AFL++ a hacer mutaciones que aumenten la cobertura del código.

Estas semillas valen tanto para la prueba con ASAN como para la prueba sin ASAN.

```bash
mkdir -p /src/seeds_iotmp

# 1) OK vacío (type=0x01, size=0) — sólo header
printf '\x01\x00' > /src/seeds_iotmp/ok_empty.bin

# 2) CONNECT con un varint (fid=1,val=1)
# body: 0x08 0x01  => key=(fid=1, wire=0) -> 0x08 ; value=0x01 ; size=2
printf '\x03\x02\x08\x01' > /src/seeds_iotmp/connect_f1v1.bin

# 3) STREAM DATA con dos varints (fid1=1,val=1) (fid2=2,val=0)
# body: 0x08 0x01 0x10 0x00  -> size=4
printf '\x0A\x04\x08\x01\x10\x00' > /src/seeds_iotmp/stream_two_var.bin

# 4) DESCRIBE con cuerpo grande (128 bytes) para forzar size varint a 2 bytes (0x80 0x01)
python3 - <<'PY'
body = bytes([0x08,0x00])*64             # 64 pares (key=0x08,val=0x00) => 128 bytes
msg  = bytes([0x07, 0x80, 0x01]) + body  # type=0x07, size=128
open('/src/seeds_iotmp/describe_128.bin','wb').write(msg)
PY

# 5) ERROR con campo fid=15 y valor 127
# key=(15<<3)|0 = 0x78; value=0x7F -> size=2
printf '\x02\x02\x78\x7f' > /src/seeds_iotmp/error_f15_127.bin

# 6) CONNECT con PSON vacío (wire type = 1), body = 0x09 0x00
# 0x09 = key con wire=1 (PSON) y fid=1; 0x00 = PSON vacío mínimo (según implementación)
# => size=2 para que encaje exactamente con el body
printf '\x03\x02\x09\x00' > /src/seeds_iotmp/connect_empty_pson.bin

# 7) RUN con stream_id=0 (varint simple), body=0x08 0x00 -> size=2
printf '\x06\x02\x08\x00' > /src/seeds_iotmp/run_sid0.bin

# 8) START con PSON vacío: body=0x09 0x00 -> size=2
printf '\x08\x02\x09\x00' > /src/seeds_iotmp/start_empty_pson.bin

```

### **4. Lanzar AFL++:**

- ***FUZZING con ASAN***
    
    Arrancamos el fuzzing indicando la carpeta de seeds y la de resultados. AFL se pondrá a variar los inputs y a “empujar” ramas nuevas del código.
    
    ```bash
    mkdir -p /src/out_iotmp_asan
    
    ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
    AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 \
    afl-fuzz -i /src/seeds_iotmp -o /src/out_iotmp_asan -m none -t 8000+ -- \
    /src/install/iotmp_harness_dbg
    ```
    
    - Usa el binario **ASAN**: `/src/install/iotmp_harness_dbg`.
    - `m none` con ASAN (evita falsos OOM).
    - `symbolize=0` para ir más rápido durante el fuzz.
    - `ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0`
        - Hace que ASAN trate cada bug como crash; desactiva los leaks (ruidosos en fuzzing); `symbolize=0` lo usamos para velocidad. Para triage pon `symbolize=1`.
    - `AFL_AUTORESUME=1`
        - Reanuda sesiones previas sin pedir confirmación si el `o` ya existe.
    - `afl-fuzz -i ... -o ... -m none -t 8000+ -- /src/install/iotmp_harness`
        - `i` seeds iniciales.
        - `o` carpeta de salida (corpus, crashes, stats).
        - `m none` sin límite de RAM (útil con ASAN). Si prefieres límite: `m 4096`.
        - `t 8000+` timeout base 8s por ejecución; el `+` deja a AFL autoajustar.
        - `-` separa flags de AFL del comando objetivo.
        - **Sin `@@`** porque tu harness lee **stdin**.
    
    <img width="1202" height="759" alt="Image" src="https://github.com/user-attachments/assets/79a89d36-9ee8-48dc-a591-1f4dbc1158b6" />
    
- ***FUZZING sin ASAN***
    
    Aquí usamos el binario sin **ASAN**: `/src/install/iotmp_harness_noasan`.
    
    ```bash
    mkdir -p /src/out_iotmp_noasan
    
    AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 \
    afl-fuzz -i /src/seeds_iotmp -o /src/out_iotmp_noasan -m 1024 -t 8000+ -- \
    /src/install/iotmp_harness_noasan
    ```
    
    - En el fuzzing con ASAN, el propio AddressSanitizer añade un gran overhead de memoria, por lo que si imponemos un límite hay riesgo de vetar ejecuciones válidas, por eso hemos utilizado `-m none` .
        
        Por el contrario, en el fuzzing sin ASAN, el binario es ligero y más rápido, por lo que un límite de memoria (como `-m 1024`) actúa como protección de seguridad: evita que entradas maliciosas provoquen consumos descontrolados de RAM o falsos positivos de OOM.
        
    
    <img width="1189" height="744" alt="Image" src="https://github.com/user-attachments/assets/b90c33e9-d891-4dbf-a35e-ce65d57caeca" />
    
- **¿Dónde guarda AFL++ los outputs que genera?**
    
    ```bash
    /src/out_iotmp_asan/default/
    ├─ fuzzer_stats        # métricas en texto
    ├─ plot_data           # series temporales para gráficas
    ├─ queue/              # corpus “vivo” (casos interesantes por cobertura)
    ├─ crashes/            # entradas que provocan crash (SIGSEGV, SIGABRT, OOM…)
    ├─ hangs/              # timeouts (no retornan en el tiempo -t)
    └─ .cur_input          # último input probado (temporal)
    ```
    

### **5. Observar y afinar:**

1. ***Minimizar POCs (ASAN y no-ASAN)***
    - ASAN:
        
        ```bash
        mkdir -p /src/iotmp_min/asan
        ```
        
        ```bash
        # Minimizar todos los crashes de la campaña ASAN contra el binario ASAN
        for c in /src/out_iotmp_asan/default/crashes/id:*; do
          b=$(basename "$c")
          afl-tmin -i "$c" -o "/src/iotmp_min/asan/$b.min" -- /src/install/iotmp_harness_dbg
        done
        ```
        
    - No-ASAN:
        
        ```bash
        mkdir -p /src/iotmp_min/noasan
        ```
        
        ```bash
        # Minimizar todos los crashes de la campaña NO-ASAN contra el binario ASAN
        # (usar ASAN para minimizar da señales de error más fiables)
        for c in /src/out_iotmp_noasan/default/crashes/id:*; do
          b=$(basename "$c")
          afl-tmin -i "$c" -o "/src/iotmp_min/noasan/$b.min" -- /src/install/iotmp_harness_dbg
        done
        ```
        
2. ***Triage con símbolos***
    - ¿En qué consiste?
        
        Ejecutar cada POC (Proof Of Concept) con el binario ASAN para que el sanitizer te diga qué tipo de bug es y dónde ocurrió (backtrace con funciones y líneas).
        
        Sirve para agrupar crashes que en realidad son el mismo bug y clasificar por tipo (heap-buffer-overflow, stack-bubffer-overflow, null-deref, etc.)
        
    1. Preparar simbolización ASAN
        
        ```bash
        SYM=$(command -v llvm-symbolizer || echo /usr/bin/llvm-symbolizer)
        export ASAN_OPTIONS="abort_on_error=1:symbolize=1:detect_leaks=0:external_symbolizer_path=$SYM"
        ```
        
    2. Volcar informe + firma por cada PoC
        
        ¿Qué hace el script?
        
        - Ejecuta el PoC con **ASAN**,
        - Extrae el **tipo de bug** (línea `ERROR: AddressSanitizer: ...`),
        - Captura las **3 primeras funciones** del backtrace como una **firma**,
        - Y guarda todo en un CSV rápido para agrupar.
        
        ```bash
        mkdir -p /src/iotmp_reports
        OUT=/src/iotmp_reports/triage_asan.csv
        echo "file,kind,signature" > "$OUT"
        
        triage_one() {
          f="$1"
          log=$(/src/install/iotmp_harness_dbg < "$f" 2>&1)
        
          # 1) Preferir clasificación ASAN
          asan_line=$(echo "$log" | grep -m1 "^ERROR: AddressSanitizer:")
          if [ -n "$asan_line" ]; then
            kind=$(echo "$asan_line" | sed 's/^ERROR: AddressSanitizer: //')
            sig=$(echo "$log" \
              | awk '/^ *#0/||/^ *#1/||/^ *#2/ {print}' \
              | grep -v "libasan\|__interceptor\|libc.so\|ld-linux" \
              | head -n 3 | sed 's/[[:space:]]\+/ /g' | tr -d '\r')
          else
            # 2) Si no hay ASAN, estimar por señal (no-ASAN crash)
            # Ejecutar con binario no-asan para capturar la señal
            /src/install/iotmp_harness_noasan < "$f" >/dev/null 2>"/tmp/noasan.err"
            rc=$?
            case $rc in
              0) kind="no-crash";;
              134) kind="sig:06 (SIGABRT)";;
              139) kind="sig:11 (SIGSEGV)";;
              *) kind="sig:?? (rc=$rc)";;
            esac
            # Firma pobre: primeras líneas con '#0/#1' si las hubiera (a veces no hay símbolos)
            sig=$(echo "$log" | awk '/^ *#0/||/^ *#1/||/^ *#2/ {print}' \
                  | head -n 3 | sed 's/[[:space:]]\+/ /g')
            [ -z "$sig" ] && sig="no-frames"
          fi
        
          echo "$(basename "$f"),$kind,\"$sig\"" >> "$OUT"
        }
        
        # Triage sobre PoCs minimizados ASAN + NO-ASAN
        for f in /src/iotmp_min/asan/*.min;   do triage_one "$f"; done
        for f in /src/iotmp_min/noasan/*.min; do triage_one "$f"; done
        
        echo "Reporte listo: $OUT"
        ```
        
3. ***Agrupar por raíz (deduplicar)***
    1. Agrupar por `asan_type + signature`:
        
        ```bash
        # Agrupar por (kind + signature)
        awk -F, 'NR>1 { gsub(/"/,""); key=$2" | "$3; cnt[key]++ } END { for(k in cnt) print cnt[k]"x  "k }' "$OUT" \
          | sort -nr > /src/iotmp_reports/triage_summary.txt
        
        echo "OK -> /src/iotmp_reports/triage_asan.csv"
        echo "OK -> /src/iotmp_reports/triage_summary.txt"
        ```
        
        - `triage_summary.txt`
        
        ```
        [AFL++ 944ec74175c9] /src # cat /src/iotmp_reports/triage_summary.txt
        146x   | 
        11x  sig:11 | src:000096
        5x  sig:11 | src:000188
        5x  sig:11 | src:000164
        5x  sig:06 | src:000125
        4x  sig:06 | src:000078
        2x  sig:11 | src:000224
        2x  sig:06 | src:000136
        2x  sig:06 | src:000127
        2x  sig:06 | src:000103
        2x  sig:06 | src:000002
        1x  sig:11 | src:000360
        1x  sig:11 | src:000359
        1x  sig:11 | src:000256
        1x  sig:11 | src:000238
        1x  sig:11 | src:000232
        1x  sig:11 | src:000230
        1x  sig:11 | src:000212
        1x  sig:11 | src:000192
        1x  sig:11 | src:000176
        1x  sig:11 | src:000156
        1x  sig:11 | src:000126
        1x  sig:11 | src:000116
        1x  sig:11 | src:000090
        1x  sig:11 | src:000049
        1x  sig:11 | src:000004
        1x  sig:06 | src:000270
        1x  sig:06 | src:000243
        1x  sig:06 | src:000240
        1x  sig:06 | src:000206
        1x  sig:06 | src:000205
        1x  sig:06 | src:000195
        1x  sig:06 | src:000185
        1x  sig:06 | src:000166
        1x  sig:06 | src:000164
        1x  sig:06 | src:000144
        1x  sig:06 | src:000139
        1x  sig:06 | src:000134
        1x  sig:06 | src:000132
        1x  sig:06 | src:000115
        1x  sig:06 | src:000098
        1x  sig:06 | src:000087
        1x  sig:06 | src:000035
        1x  sig:06 | src:000004
        ```
        
        - **Interpretación:**
            - `sig:11 | src:000096` → signal 11 (SIGSEGV), el caso se originó a partir del input scr:000096
            - `sig:06 | src:000125` → signal 6 (SIGABRT), …
            - `146x |` → clave vacía (no se extrajo ni tipo de ASAN ni señal). Suele pasar si:
                - Ejecutaste algunos PoC **sin ASAN** en el paso de triage (entonces no hay línea `ERROR: AddressSanitizer:` y tu parser no detectó la señal), o
                - El parser de logs no encontró ninguna coincidencia y dejó la clave en blanco.
            
            <img width="632" height="92" alt="Image" src="https://github.com/user-attachments/assets/c305eab1-1370-4304-9114-f3aa6847695a" />
            
        - `sig:11`→ signal 11 (SIGSEGV) → acceso inválido a memoria
        - `sig:06`→ signal 6 (SIGABRT) → abort, típicamente lo provoca ASAN al detectar corrupción o un `assert/abort()` .
        
4. ***Confirmar “crash real” (sin ASAN)***
    
    Queremos convertir los archivos de `crashes/` en **pocos bugs** bien explicados
    
    1. Para los grupos principales (1 POC representativo de cada firma), ejecutar el binario no ASAN y mirar la señal:
        
        ```bash
        for p in /src/iotmp_min/asan/*.min; do
          /src/install/iotmp_harness_noasan < "$p" >/dev/null 2>&1
          rc=$?
          if [ $rc -ne 0 ]; then echo "CRASH(noasan) $p (rc=$rc)"; fi
        done
        ```
        
        Salida:
        
        ```
        [AFL++ 944ec74175c9] /src # for p in /src/iotmp_min/asan/*.min; do
          /src/install/iotmp_harness_noasan < "$p" >/dev/null 2>&1
          rc=$?
          if [ $rc -ne 0 ]; then echo "CRASH(noasan) $p (rc=$rc)"; fi
        done
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000000,sig:06,src:000004,time:23998,execs:11284,op:havoc,rep:3.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000001,sig:06,src:000078,time:109480,execs:53075,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000002,sig:06,src:000078,time:112699,execs:54574,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000003,sig:06,src:000078,time:114547,execs:55443,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000004,sig:06,src:000078,time:116304,execs:56263,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000005,sig:06,src:000098,time:131504,execs:63365,op:havoc,rep:5.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000006,sig:06,src:000103,time:134022,execs:64553,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000007,sig:06,src:000103,time:142372,execs:68474,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000008,sig:06,src:000125,time:164583,execs:78843,op:havoc,rep:3.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000009,sig:06,src:000125,time:173667,execs:83084,op:havoc,rep:4.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000010,sig:06,src:000125,time:181492,execs:86775,op:havoc,rep:4.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000011,sig:06,src:000125,time:185094,execs:88445,op:havoc,rep:3.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000012,sig:06,src:000125,time:188453,execs:90012,op:havoc,rep:4.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000013,sig:06,src:000139,time:213629,execs:102020,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000014,sig:06,src:000035,time:232456,execs:110952,op:havoc,rep:14.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000015,sig:06,src:000136,time:232899,execs:111164,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000016,sig:06,src:000136,time:234164,execs:111764,op:havoc,rep:15.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000017,sig:06,src:000087,time:239620,execs:114267,op:quick,pos:8,val:+16.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000018,sig:06,src:000185,time:244414,execs:116430,op:havoc,rep:4.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000019,sig:06,src:000144,time:246090,execs:117209,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000020,sig:06,src:000002,time:270405,execs:128538,op:havoc,rep:7.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000021,sig:06,src:000002,time:289206,execs:136947,op:havoc,rep:5.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000022,sig:06,src:000127,time:295317,execs:139772,op:havoc,rep:3.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000023,sig:06,src:000164,time:301004,execs:142456,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000024,sig:06,src:000115,time:361839,execs:169176,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000025,sig:06,src:000206,time:418688,execs:195594,op:havoc,rep:8.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000026,sig:06,src:000134,time:452554,execs:211479,op:havoc,rep:14.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000027,sig:06,src:000127,time:469491,execs:219445,op:havoc,rep:14.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000028,sig:06,src:000205,time:530126,execs:248138,op:havoc,rep:9.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000029,sig:06,src:000132,time:567613,execs:266203,op:havoc,rep:2.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000030,sig:06,src:000166,time:571595,execs:268107,op:havoc,rep:6.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000031,sig:06,src:000243,time:583426,execs:273773,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000032,sig:06,src:000240,time:639754,execs:299510,op:havoc,rep:1.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000033,sig:06,src:000195,time:669094,execs:312968,op:havoc,rep:14.min (rc=139)
        Segmentation fault (core dumped)
        CRASH(noasan) /src/iotmp_min/asan/id:000034,sig:06,src:000270,time:822130,execs:374929,op:havoc,rep:3.min (rc=139)
        ```
        
        - Interpretación:
            
            La lista `CRASH(noasan) ... (rc=139)` confirma muchas reproducciones SIGSEGV sin ASAN para POCs minimizados; lo que es un indicador de potencial DoS.
            

### 6. Conclusión:

En las dos pruebas ejecutadas con AFL++ (con y sin ASAN) se registraron *crashes*, lo que confirma que el *decoder* de IOTMP tiene rutas de ejecución frágiles ante entradas malformadas. Con ASAN se guardaron 35 *crashes* y sin ASAN 38, con coberturas más o menos similares (alrededor del 26% con ASAN, frente a 21% sin ASAN). Es esperable que la campaña sin ASAN reporte más *crashes*, ya que el programa se ejecuta más rápido y cualquier corrupción en memoria termina provocando errores visibles. Por el contrario, ASAN ralentiza la ejecución, pero ofrece información más clara sobre el origen de los fallos, lo que facilita su análisis.

Los fallos observados se son SIGSEGV (segmentation fault) y SIGABRT, ambos problemas típicos de memoria. En resumidas cuentas, estos errores indican que el programa intentó leer o escribir en posiciones de memoria que no debía, acceder a datos inexistentes o manejar estructuras internas que estaban incompletas o dañadas. Todo esto apunta a una validación insuficiente de las longitudes y límites de los mensajes recibidos.

Estos resultados evidencian un riesgo claro de denegación de servicio (DoS), ya que un atacante podría provocar la caída del proceso con entradas malformadas. Como medidas de mejora inmediatas, sería recomendable reforzar las comprobaciones sobre el tamaño de los mensajes, rechazar de forma estricta entradas imposibles y asegurarse de que, si un mensaje llega corrupto, el sistema lo descarte de forma segura en lugar de bloquearse.
