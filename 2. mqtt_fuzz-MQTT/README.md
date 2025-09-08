## Sobre mqtt_fuzz

*mqtt_fuzz* es una herramienta de código abierto creada originalmente por Antti Vähä-Sipilä con el objetivo de evaluar la seguridad de las implementaciones del protocolo MQTT. Está pensada específicamente para ejecutar campañas de fuzzing contra *brokers* MQTT, enviando mensajes modificados o malformados para comprobar si el servidor los gestiona de forma correcta o se producen fallos inesperados. Esta herramienta se ha utilizado en numerosos proyectos de investigación sobe el Internet de las Cosas, puesto que MQTT es uno de los protocolos más populares en este ámbito.

La herramienta combina dos componentes clave: por un lado, el motor de mutación *Radamsa*, que genera variaciones aleatorias o semiestructuradas a partir de mensajes válidos (*seeds*) de MQTT; y por otro, la librería *Twisted*, que ofrece una infraestructura de red asíncrona en Python para gestionar las conexiones con el *broker* y el envío masivo de mensajes. Gracias a esta integración, *mqtt_fuzz* permite generar un gran volumen de tráfico anómalo de forma controlada y estudiar la reacción del servidor, facilitando la detección de vulnerabilidades como caídas, bloqueos o fallos en la validación de entradas.

---

## Repositorios de mqtt_fuzz y de Radamsa

https://github.com/WithSecureOpenSource/mqtt_fuzz

https://gitlab.com/akihe/radamsa

---

## Pasos para realizar la prueba

### 0. Pasos previos

En este caso, hay que llevar a cabo bastantes procesos antes de proceder al fuzzing:

1. Instalar Radamsa
    
    ```bash
    git clone https://gitlab.com/akihe/radamsa.git
    cd radamsa && make
    sudo make install   # opcional, puedes usar bin/radamsa
    radamsa --help
    ```
    
    ```bash
    sudo apt-get install gcc make git wget
    git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && sudo make install
    echo "HAL 9000" | radamsa
    ```
    
    Comprobar que el motor de mutación funciona:
    
    ```bash
    echo "HELLO" | radamsa --seed 4
    ```
    
    - Siempre que se fije la misma semilla (`-seed 4`), se obtendrá el mismo resultado.
    
    ![image.png](attachment:c573ad8e-2885-44b2-9ac8-3d684808fd90:image.png)
    
    ![image.png](attachment:bfcaefd6-fe72-4574-b31e-808bacbaebc7:image.png)
    
2. Instalar mqtt_fuzz:
    - mqtt_fuzz requiere:
        - Radamsa → ya instalado
        - Twisted → se instala desde el fichero `requirements.txt` del repositorio
    
    > **No se puede instalar librerías Python directamente en el sistema** porque Kali (y otras distros modernas) vienen con **PEP 668** activado. Eso protege el entorno del sistema para que no se rompan dependencias internas de la distribución.
    
    Por ello, se creará un ***virtualenv aislado*** en el que se instalará todo con ***pip***.
    > 
    1. Crear y activar el virtualenv
        
        ```bash
        # 1) Instalar el módulo venv
        sudo apt update
        sudo apt install -y python3-venv
        
        # 2) Crear el entorno
        python3 -m venv ~/venvs/mqtt_fuzz_env
        
        # 3) Activar el entorno
        source ~/venvs/mqtt_fuzz_env/bin/activate
        
        # 4) Actualizar pip/setuptools/wheel dentro del venv
        pip install --upgrade pip setuptools wheel
        
        # *) Para desactivarlo
        # source ~/venvs/mqtt_fuzz_env/bin/deactivate
        ```
        
    2. Incluir Radamsa en el PATH para que sea accesible desde cualquier parte del sistema
        
        ```bash
        # Kali Linux usa por defecto ZSH en lugar de Bash
        echo 'export PATH="$HOME/radamsa/bin:$PATH"' >> ~/.zshrc
        # y recarga
        source ~/.zshrc
        ```
        
        ![image.png](attachment:e7891bf6-fd4b-4c0f-b35c-9c953b5c3730:image.png)
        
    3. Instalar mqtt_fuzz y sus dependencias dentro del entorno virtual creado
        
        ```bash
        # Activar el venv si no lo está ya:
        source ~/venvs/mqtt_fuzz_env/bin/activate
        
        # 1) Clonar el repo
        git clone https://github.com/WithSecureOpenSource/mqtt_fuzz.git
        cd mqtt_fuzz
        
        # 2) Instalar dependencias del proyecto (dentro del venv)
        pip install -r requirements.txt
        ```
        
        ![image.png](attachment:73f80958-9ccb-4269-b725-188e3a08eb6e:image.png)
        

1. Comprobación rápida de que todo está bien instalado
    - Si los 3 checks salen bien, el entorno está listo
        
        ```bash
        # 1) ¿Twisted instalado en el venv?
        python -c "import twisted, sys; print('Twisted OK', twisted.__version__)"
        
        # 2) ¿mqtt_fuzz arranca y muestra ayuda?
        python mqtt_fuzz.py --help | sed -n '1,30p'
        
        # 3) ¿Radamsa visible desde el venv?
        which radamsa
        radamsa --help | head -n 1
        ```
        
        ![image.png](attachment:0b18c5aa-0f6a-489b-8111-52389fde452b:image.png)
        

### 1. Crear un dispositivo MQTT en Thinger y confirmar que se puede conectar

Antes de ejecutar las pruebas, queremos comprobar que un dispositivo se puede conectar al broker MQTT de Thinger a través del protocolo MQTT.

Esto también no servirá para validar las credenciales.

1. Crear un dispositivo en el dashboard de la plataforma
    
    ![image.png](attachment:c03463bb-1fd9-48b6-8aa6-2a0fbd8aaeb0:image.png)
    
2. Guardar las credenciales como variables de entorno y probar una publicación simple:
    
    ```bash
    export THINGER_HOST=10.0.2.15
    export THINGER_PORT=1883           # usa 1883 para capturar CONNECT en claro
    export THINGER_USER=arturo_100432160      # (no el email)
    export THINGER_DEVICE_ID=esp32test     # client-id
    export THINGER_DEVICE_PW=123456    # credencial del device
    ```
    
    - Debemos utilizar el puerto 1883 de tu Thinger (sin TLS [puerto 8883]) para capturar CONNECT fácilmente y poder ver el mensaje en claro
    
    ```bash
    mosquitto_pub -d \
      -h "$THINGER_HOST" -p "$THINGER_PORT" \
      -i "$THINGER_DEVICE_ID" \
      -u "$THINGER_USER" -P "$THINGER_DEVICE_PW" \
      -V mqttv311 \
      -t sanity/test -m '{"ok":1}'
    ```
    
    ![image.png](attachment:759abb75-e1b8-47fd-aeb9-297c5f3475cb:image.png)
    
3. Si quisiésemos ver en otra terminal como se publican los mensajes, podríamos suscribirnos al mismo en la otra terminal tema de la siguiente manera:
    
    ```bash
    export THINGER_HOST=10.0.2.15
    export THINGER_PORT=1883           # usa 1883 para capturar CONNECT en claro
    export THINGER_USER=arturo_100432160      # (no el email)
    export THINGER_DEVICE_ID=esp32sub     # client-id
    export THINGER_DEVICE_PW=123456    # credencial del device
    ```
    
    ```bash
    mosquitto_sub -d \
      -h "$THINGER_HOST" -p "$THINGER_PORT" \
      -i "$THINGER_DEVICE_ID" \
      -u "$THINGER_USER" -P "$THINGER_DEVICE_PW" \
      -V mqttv311 \
      -t 'sanity/#' -v
    ```
    
    ![image.png](attachment:9114ebef-cf3c-4c2a-891d-d49e7a50341e:image.png)
    

### 2. Generar semillas válidas desde tráfico real con *tshark*

Para asegurarnos de que la semillas que utilicemos durante el fuzzing sean válidas, capturaremos tráfico real MQTT con la herramienta *tshark* y guardaremos esas capturas como binarios (mqtt_fuzz requiere que las semillas estén en binario).

Esta prueba se va a separar en distintos grupos, según el tipo de mensaje MQTT. Se ha decidido formar 5 grupos que agrupan los siguientes tipos de mensaje (además se incluye los casos base que se han elegido para cada tipo de mensaje):

- **CONNECT/CONNACK**
    - CONNECT básico con Auth
    - CONNECT con CleanSession=0 (persistencia)
    - CONNECT con Will
    - CONNECT con KeepAlive=5 (mínimo) y KeepAlive=65535 (máximo)
    - CONNECT con ClientId largo (32 caracteres, el máximo)
- **PUBLISH**
    - QoS0, payload pequeño, topic 1 nivel (a)
    - QoS0 retained=1, topic ‘retained/topic’, payload ‘R’
    - QoS1, payload medio (~2-4KB), topic 2 niveles (a/b)
    - QoS2, payload pequeño, topic 3 niveles (a/b/c)
- **SUBSCRIBE/UNSUBSCRIBE**
    - SUBSCRIBE a un tema simple (QoS0), topic (a)
    - SUBSCRIBE a varios temas en un mismo paquete (QoS1)
    - SUBSCRIBE con QoS2
    - UNSUBSCRIBE de un tema válido (a/b)
    - UNSUBSCRIBE multitema
- **PING/DISCONNECT**
    - PINGREQ (forzado con keepalive bajo)
    - DISCONNECT (graceful)
- **QoS2 Handshake**
    - Toda la secuencia del handshake QoS2 (PUBLISH → PUBREC→ PUBREL → PUBCOMP)

Cada tipo de mensaje MQTT, tiene un código `mqtt.msgtype` distinto y una forma de enviar el mensaje (sub/pub, flags, …) diferente. Por ello, cada seed requiere una secuencia distinta para ser capturada.

![image.png](attachment:3e78249f-b8a6-4592-987d-374642cb43a4:image.png)

No obstante aquí se presenta el caso básico (CONNECT básico con Auth):

```bash
#################################################################
### TERMINAL A
#################################################################
# Asegurar variables
export THINGER_HOST=10.0.2.15
export THINGER_PORT=1883
export THINGER_USER=arturo_100432160
export THINGER_DEVICE_ID=esp32test
export THINGER_DEVICE_PW=123456

# Terminal A — capturar tráfico en 1883
sudo tshark -i any -f "tcp port $THINGER_PORT" -w /tmp/connect_auth.pcapng

#################################################################
### TERMINAL B
#################################################################
export THINGER_HOST=10.0.2.15
export THINGER_PORT=1883
export THINGER_USER=arturo_100432160
export THINGER_DEVICE_ID=esp32test
export THINGER_DEVICE_PW=123456

mosquitto_pub -d \
  -h "$THINGER_HOST" -p "$THINGER_PORT" \
  -i "$THINGER_DEVICE_ID" \
  -u "$THINGER_USER" -P "$THINGER_DEVICE_PW" \
  -V mqttv311 \
  -t sanity/cap -m 'cap'
  
#################################################################
### TERMINAL A (de nuevo)
#################################################################
# Extraer el primer paquete CONNECT (msgtype==1) -> hex -> binario -> base64
# Usando el payload TCP crudo
sudo tshark -r /tmp/connect_auth.pcapng -Y 'mqtt and mqtt.msgtype==1' \
  -T fields -e tcp.payload \
| head -n1 | tr -d ':' | xxd -r -p | base64 \
> ~/mqtt_fuzz/valid-cases/connect/connect_auth.b64

# Comprobar que hay contenido:
wc -c ~/mqtt_fuzz/valid-cases/connect/connect_auth.b64
head -n1 ~/mqtt_fuzz/valid-cases/connect/connect_auth.b64

# Pasar de Base64 a Binario
base64 -d connect_auth.b64 > connect_auth.bin
```

Básicamente en una terminal A se empieza a escuchar, y se captura un mensaje MQTT enviado desde una terminal B.

El resto de procedimientos para capturar las demás seeds estarán detallados en el directorio `seed-capture/` .

### 3. Ejecutar las pruebas por bloques

Para ejecutar cada bloque de pruebas nos ayudaremos de un script que automatiza la ejecución de la prueba, la captura de logs y facilita el análisis de los resultados. Para ejecutar este script debemos establecer ciertos parámetros (se han establecido los mismos valores para todos los bloques):

- Duración de la prueba → 180 segundos
- Fuzz ratio → 1 (de cada 10 mensajes enviados, 1 de ellos es generado por el fuzzer)
- Delay → 30ms tiempo entre mensajes enviados al broker

Cabe destacar también que para la ejecución por bloques es necesario modificar el script original `mqtt_fuzz.py` para incluir en el array `session_structure` solo aquellos tipos de mensaje que se quieren fuzzear en cada bloque:

```python
    session_structures = [['connect', 'disconnect']]			# CONNECT
    # session_structures = [['connect','publish','disconnect']]		# PUBLISH
    # session_structures = [['connect','subscribe','disconnect'],	 ['connect','unsubscribe','disconnect']]					# SUB/UNSUB	
    # session_structures = [['connect','ping','disconnect'], ['connect','disconnect']]	# PING, DISCONNECT
    # session_structures = [['connect','qos2','disconnect']]		# QOS2 HANDSHAKE
```

Este es el script utilizado para ejecutar las pruebas (`run_mqtt_fuzz.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# ===================== Config =====================
HOST="${THINGER_HOST:-10.0.2.15}"
PORT="${THINGER_PORT:-1883}"
VENV="${VENV_PATH:-$HOME/venvs/mqtt_fuzz_env}"
RADAMSA_BIN="${RADAMSA_BIN:-$HOME/radamsa/bin/radamsa}"

# Ruta raíz donde están TODAS tus carpetas de semillas (connect/, publish/, subscribe/, …)
# Ojo: mqtt_fuzz.py usará SOLO lo que tengas activado en session_structures.
VALIDCASES_DIR="${VALIDCASES_DIR:-$PWD/valid-cases}"

# Parámetros fuzz
RATIO="${RATIO:-1}"          # 0..10 (por cada 10 paquetes)
DELAY_MS="${DELAY_MS:-30}"   # milisegundos entre envíos
DURATION_SEC="${DURATION_SEC:-300}"  # duración campaña

# Nombre base para los logs de esta ejecución (p.ej. "connect", "publish", "subunsub", "qos2", etc.)
LOGS_NAME="${LOGS_NAME:-run}"   # <-- ¡cámbialo al lanzar! LOGS_NAME=connect ./run...

# Logging
LOGDIR="${LOGDIR:-$PWD/campaign_logs}"
mkdir -p "$LOGDIR"
TMPDIR="$LOGDIR/tmp"; mkdir -p "$TMPDIR"; export TMPDIR

# (Deprecated en esta versión) Broker logging opcional vía docker
# Se mantiene la variable por compatibilidad pero NO se usa para capturar.
BROKER_CID="${BROKER_CONTAINER_ID:-}"

TS="$(date +%s)"

FUZZ_LOG="$LOGDIR/fuzz-${LOGS_NAME}.log"
BROKER_LOG="$LOGDIR/broker-${LOGS_NAME}.log"   # se creará vacío
TYPE_COUNTS="$LOGDIR/types-${LOGS_NAME}.txt"
SUMMARY="$LOGDIR/summary-${LOGS_NAME}.txt"

# ===================== Pre-checks =====================
[[ -x "$RADAMSA_BIN" ]] || { echo "ERROR: radamsa en $RADAMSA_BIN no existe"; exit 1; }
[[ -d "$VALIDCASES_DIR" ]] || { echo "ERROR: validcases $VALIDCASES_DIR no existe"; exit 1; }
[[ -f "$VENV/bin/activate" ]] || { echo "ERROR: venv $VENV no existe"; exit 1; }

# ===================== Broker log (solo crear archivo vacío) =====================
: > "$BROKER_LOG"   # crea/limpia el fichero para que exista pero no lo rellenamos

# ===================== Lanzar fuzz =====================
source "$VENV/bin/activate"
echo "==> MQTT fuzz contra $HOST:$PORT"
echo "    ratio=$RATIO  delay=${DELAY_MS}ms  dur=${DURATION_SEC}s"
echo "    valid-cases:  $VALIDCASES_DIR"
echo "    Logs:"
echo "      - $FUZZ_LOG"
echo "      - $BROKER_LOG (manual)"
echo "      - $SUMMARY"
echo "      - $TYPE_COUNTS"

# Aviso por si existe ya un log previo con el mismo nombre
if [[ -s "$FUZZ_LOG" ]]; then
  echo "WARN: $FUZZ_LOG ya existe y tiene contenido. Se sobrescribirá."
fi

# Ejecuta y guarda el log del fuzzer
timeout --preserve-status "$DURATION_SEC" \
python mqtt_fuzz.py \
  -validcases "$VALIDCASES_DIR" \
  -fuzzer "$RADAMSA_BIN" \
  --valid-connect \
  -ratio "$RATIO" \
  -delay "$DELAY_MS" \
  "$HOST" "$PORT" | tee "$FUZZ_LOG" || true

# ===================== Resumen =====================
echo "==> Generando resumen..."

TOTAL_LINES=$(wc -l < "$FUZZ_LOG")
CONN_EVENTS=$(grep -c -E 'Connected to server' "$FUZZ_LOG" || true)
CONNACKS=$(grep -c -E 'Server -> Fuzzer:' "$FUZZ_LOG" || true)
CLOSED_CLEAN=$(grep -c -E 'closed cleanly|ConnectionDone' "$FUZZ_LOG" || true)
CONN_LOST=$(grep -c -E 'Connection to MQTT server lost' "$FUZZ_LOG" || true)
RECONNECTS=$(grep -c -E '^.*Reconnecting' "$FUZZ_LOG" || true)
FWD_PKTS=$(grep -c -E '^.*Fuzzer -> Server:' "$FUZZ_LOG" || true)
SESSIONS=$(awk 'match($0,/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/,m){u[m[0]]=1} END{print length(u)}' "$FUZZ_LOG")

# Conteo por tipo MQTT (decodificando el primer byte del frame base64)
python - "$FUZZ_LOG" "$TYPE_COUNTS" <<'PY'
import sys, base64, re, collections
log = sys.argv[1]; out = sys.argv[2]
b64re = re.compile(rb"Fuzzer -> Server: b'([A-Za-z0-9+/=]+)'")
counts = collections.Counter()
mapname = {
  0x10:'CONNECT', 0x20:'CONNACK', 0x30:'PUBLISH', 0x40:'PUBACK',
  0x50:'PUBREC',  0x60:'PUBREL',  0x70:'PUBCOMP', 0x80:'SUBSCRIBE',
  0x90:'SUBACK',  0xA0:'UNSUBSCRIBE', 0xB0:'UNSUBACK',
  0xC0:'PINGREQ', 0xD0:'PINGRESP',   0xE0:'DISCONNECT'
}
with open(log,'rb') as f:
    for line in f:
        m = b64re.search(line)
        if not m: continue
        try:
            raw = base64.b64decode(m.group(1), validate=True)
            if not raw: continue
            b0 = raw[0] & 0xF0  # nibble alto identifica tipo
            name = mapname.get(b0, f"0x{b0:02X}")
            counts[name]+=1
        except Exception:
            pass
with open(out,'w') as g:
    for k,v in counts.most_common():
        g.write(f"{k}: {v}\n")
PY

cat > "$SUMMARY" <<EOF
==== MQTT_FUZZ SUMMARY ====
Target            : $HOST:$PORT
Started (epoch)   : $TS
Duration (sec)    : $DURATION_SEC
Ratio (per 10)    : $RATIO
Delay (ms)        : $DELAY_MS
Validcases root   : $VALIDCASES_DIR

Fuzz log          : $FUZZ_LOG
Broker log (manual): $BROKER_LOG

Total log lines   : $TOTAL_LINES
Sessions (UUID)   : $SESSIONS
Connect events    : $CONN_EVENTS
CONNACK replies   : $CONNACKS
Fuzzer->Server pkts: $FWD_PKTS
Conn lost events  : $CONN_LOST
Cleanly closed    : $CLOSED_CLEAN
Reconnections     : $RECONNECTS

MQTT type counts  : $TYPE_COUNTS
===========================
EOF

cat "$SUMMARY"
echo "==> Done."
```

Le damos permisos de ejecución y lanzamos el fuzzing:

```python
cd ~/mqtt_fuzz
chmod +x ./run_mqtt_fuzz.sh

# 3 min, fuzz-ratio=1, delay=30ms
LOGS_NAME='connect' \
DURATION_SEC=180 RATIO=1 DELAY_MS=30 \
./run_mqtt_fuzz.sh
```

Para observar los logs del broker MQTT de Thinger:

```bash
docker logs -f <container-id>
```

### 4. Resultados

- **Prueba CONNECT**
    
    ![image.png](attachment:47cb37ce-96c2-451f-bbb8-8aa6eaae1f4a:image.png)
    
    - En *log* del *fuzzer* aparece “Connection to MQTT server lost: … Connection Done”. Esto podría parecer un error, pero es el ciclo normal de cierre que ocurre cuando el *fuzzer* envía el DISCONNECT.
    - Aparecen muchos más CONNECTs enviados que ‘Sessions’, no obstante, esto tiene sentido. El nº de sesiones es el número de veces que el *fuzzer* abre un *socket* TCP y llega al estado “Connected to server”. Por otra parte, en nº de CONNECTs enviado es el total de frames MQTT de este tipo que el fuzzer inyecta por el socket. Mientras ya hay una sesión abierta, el *fuzzer* sigue inyectando CONNECTs aunque el broker no los vaya a aceptar, por eso es normal que hay bastantes más.
    - El *log* del *broker* solo contiene mensajes de “INFO|”, no contiene ninguno de “ERR|”, por lo que parece que no ha registrado ningún error.
    - Todos los CONNACKs tienen “rc_ok”, por lo que no se ha rechazado ninguna conexión.
    - Todas las sesiones que se abren se cierran limpiamente (a excepción de la última que no llegará a cerrarse por el fin de ejecución del *script*).
    
- **Prueba PUBLISH**
    
    ![image.png](attachment:40511fb7-7e32-4293-b71d-7606d2e6c792:image.png)
    
    - En este caso tampoco aparecen errores ni excepciones en el *log* del *broker*.
    - En el *log* del *fuzzer* vuelven a aparecer los mensajes de “Connection to MQTT server lost: …”, que como se ha mencionado antes, son completamente normales.
    - Cabe destacar la diferencia que ofrece el resumen de ejecución del *script* entre “CONNACK replies: 1519” y “connack_seen_total: 1004”. El segundo se corresponde con el número de sesiones (UUIDs) únicos que se han abierto, mientras que el primero se corresponde con el total de CONNACKs total que se han registrado (el *broker* en algunos casos responde con un CONNACK extra a esos CONNECTs redundantes que envía el *fuzzer)*.
    - Todos los CONNACKs tienen “rc_ok”, por lo que no se ha rechazado ninguna conexión.
    - Todas las sesiones abiertas se llegan a cerrar limpiamente a excepción de la última.
    
- **Prueba SUBSCRIBE/UNSUBSCRIBE**
    
    ![image.png](attachment:29c09f0e-8374-4bd8-9644-0b3757f09de4:image.png)
    
    - Todos los CONNACKs tienen “rc_ok”, por lo que no se ha rechazado ninguna conexión.
    - Todas las sesiones abiertas se llegan a cerrar limpiamente a excepción de la última.
    - El *log* del *fuzzer* no mostró errores.
    - El *log* del *broker* mostró bastantes errores, pero todos ellos se corresponden con el error que ocurre cuando el cliente intenta hacer UNSUBSCRIBE de un tema que no existe, lo que quiere decir que el *broker* valida correctamente.
        
        ```bash
        ERR| unsubscribe request to a non registered topic: a/b
        ERR| unsubscribe request to a non registered topic: sensors/+/temp
        ERR| unsubscribe request to a non registered topic: logs/#
        ```
        
    - “El único hallazgo destacable es la generación masiva de errores por UNSUBSCRIBE no registrados, que podría considerarse un vector potencial de denegación de servicio por *log flooding*.”
    
- **Prueba PINGREQ/DISCONNECT**
    
    ![image.png](attachment:38bbb859-2d28-4c3c-b1ca-40f4a66bfdd5:image.png)
    
    - Todos los CONNACKs tienen “rc_ok”, por lo que no se ha rechazado ninguna conexión.
    - Todas las sesiones abiertas se llegan a cerrar limpiamente.
    - El *fuzzer* no muestra errores en el *log*.
    - El *broker* no muestra mensajes de error ni advertencias.
    - El *broker* nunca se bloquea ante PINGREQ inválidos, simplemente no responde y mantiene el control de la sesión.
    - El spam masivo de DISCONNECT/CONNECT obliga al *broker* a procesar miles de ciclos de conexión, lo que aumenta el consumo de CPU y la cantidad de logs (*log flooding*). Esto no tumba el servicio, pero podría ralentizarlo bajo ataques prolongados (**Posible vector DoS**).
    
- **Prueba QoS2 Handshake**
    
    ![image.png](attachment:1772acec-c56b-46b1-8b29-8a685c40d8e3:image.png)
    
    - Todos los CONNACKs tienen “rc_ok”, por lo que no se ha rechazado ninguna conexión.
    - Todas las sesiones abiertas se llegan a cerrar limpiamente.
    - El *log* del *broker* muestra bastantes errores como estos:
    
    ```bash
    ERR| received a publish for non existing message: 1
    ERR| received a publish acknowledgement from a non existing message: 1
    ERR| received a publish release from a non existing message: 1
    ```
    
    - Estos errores no son preocupantes, son logs internos de manejo de inconsistencias en el flujo de QoS2. Esto ocurre cuando el *broker* esperaba el *MessageID* de un mensaje concreto, y recibe el de otro que no había visto nunca o ya había cerrado. Esta situación también puede darse porque el fuzzer genere secuencias inválidas (p.e., enviar un PUBREL sin haber enviado un PUBREC).
        
        Ante esta situación, el *broker* responde de forma defensiva cerrando la sesión, liberando recursos, y volviendo a reconectar.
        
    - La aparición de tantos errores, bajo un ataque real, podrían generar un *log flooding* saturando el almacenamiento.
    - Un atacante podría enviar miles de mensajes QoS2 malformados, forzando al *broker* a cerrar y reabrir sesiones continuamente, lo que aumenta la carga de CPU y *logs* (posible vector DoS leve).
    

### 5. Conclusiones

En conjunto, las pruebas realizadas con *mqtt_fuzz* muestran que la implementación de MQTT en Thinger.io se comporta de forma robusta frente a entradas inválidas o manipuladas, rechazando adecuadamente los mensajes que no cumplen con el formato o que incluyen parámetros inconsistentes. En la mayoría de los casos, las sesiones se establecen y cierran de manera limpia, sin que se produzcan bloqueos ni caídas del *broker*, lo que refleja un manejo correcto del protocolo. Los únicos hallazgos reseñables son la acumulación de mensajes de error cuando se intentan operaciones no válidas (por ejemplo, UNSUBSCRIBE a *topics* inexistentes o secuencias incoherentes en el *handshake* QoS2), así como la posibilidad de generar una gran cantidad de logs o un aumento en el consumo de CPU si se realizan ataques masivos de conexiones repetidas. Aunque estos escenarios no comprometen directamente la estabilidad del servicio, sí podrían aprovecharse como vectores de denegación de servicio ligera (DoS) en un ataque sostenido.
