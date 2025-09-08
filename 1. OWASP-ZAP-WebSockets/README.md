## Sobre OWASP ZAP

OWASP ZAP (*Zed Attack Proxy*) es una herramienta de seguridad muy conocida dentro del mundo del pentesting. Se trata de un proyecto de código abierto mantenido por la comunidad OWASP (*Open Web Application Security Project*), lo que asegura tanto su evolución constante como su accesibilidad. ZAP es capaz de interceptar, modificar y reenviar el tráfico entre un cliente (normalmente el navegador) y el servidor, por lo que es especialmente interesante para analizar aplicaciones web. En otras palabras, este programa actúa como un “*proxy* intermediario” que permite observar en detalle qué mensajes se están intercambiando y manipularlos para comprobar cómo responde el sistema ante estas modificaciones. [CITA??]

Una de sus grandes ventajas es que es una herramienta multiplataforma, con versiones para Windows, Linux y macOS, e incluso tiene imágenes listas para usar en Docker. Todo esto la convierte en una herramienta muy útil tanto para principiantes que buscan introducirse en el análisis de seguridad como para especialistas que requieren un entorno de pruebas más completo. Además, cuenta con numerosos complementos (*add-ons*) que amplían sus funcionalidades y permiten adaptarla a otros casos de uso.

ZAP ofrece varios modos de análisis. Por un lado, el **escaneo pasivo**, que se limita a inspeccionar las peticiones y respuestas que pasan a través del proxy sin alterarlas (enfoque no intrusivo). Por otro, el **escaneo activo**, que realiza ataques más directos para intentar descubrir vulnerabilidades conocidas, aunque esto puede llegar a afectar al funcionamiento del servicio que se está probando. Por último, ZAP incorpora un **fuzzer** integrado, con el que es posible enviar grandes cantidades de datos malformados o inesperados a los servicios web y analizar cómo estos reaccionan. Esta última funcionalidad es la que se empleará en este trabajo, generando mensajes alterados y enviándolos al servidor de Thinger.io para observar sus reacciones.

En resumen, OWASP ZAP es una herramienta muy adecuada para analizar las comunicaciones WebSocket de Thinger.io, ya que este protocolo se utiliza en su consola web para mantener actualizada en tiempo real la información de los dispositivos conectados. Además, la herramienta también puede aplicarse al análisis de protocolos como HTTP, lo que la hace bastante versátil. La combinación de facilidad de uso y potentes funciones de interceptación, análisis y fuzzing, convierten a ZAP en un recurso clave para evaluar la implementación de estos protocolos y detectar posibles debilidades en su seguridad.

---

### Web oficial de ZAP

[ZAP – Download](https://www.zaproxy.org/download/)

---

### Artículos y enlaces interesantes sobre el uso de OWASP ZAP

[OWASP ZAP: Guía de descarga, instalación y funcionalidades](https://www.pragma.co/es/blog/guia-de-uso-de-owasp-zap)

[Escaneo de vulnerabilidades automático con OWASP ZAP](https://academy.seguridadcero.com.pe/blog/escaneo-vulnerabilidades-autom%C3%A1tico-OWASP-ZAP)

[Uso de OWASP-ZAP | INCIBE-CERT | INCIBE](https://www.incibe.es/incibe-cert/seminarios-web/uso-owasp-zap)

[ZAP DeepDive: WebSockets](https://www.youtube.com/watch?v=LDm0Fst81hU)

---

## Pasos para realizar la prueba

### 0. Pasos previos

1. Instalar ZAP desde la página oficial.
2. Lanzar ZAP
    
    ```bash
    ~/zap/ZAP_2.16.1/zap.sh
    ```
    
3. Configurar el navegador para que utilice el proxy generado por ZAP (por defecto, en el puerto 8080).
    
    Esto permitirá a la herramienta registrar todo el tráfico de entrada y salida del navegador.
    
    ![image.png](attachment:b7fbc30c-f8c3-4d7d-8a93-a8bd7293ed1b:image.png)
    
4. Generar un certificado SSL con ZAP e importarlo al navegador.
    
    Este permitirá capturar también tráfico SSL, de lo contrario, el navegador rechazaría cualquier conexión cifrada cuyo certificado no sea conocido.
    
    ![image.png](attachment:09c27793-1114-40bf-b05e-34bb43d85fde:image.png)
    
    ![image.png](attachment:07e2d601-55d7-4ccb-9df0-fb34ed74c143:image.png)
    
    ![image.png](attachment:02e9bee9-6efc-4ae0-9789-933aad54c6e3:image.png)
    

### 1. Ejecutar las pruebas con la herramienta

Se ha decidido descomponer el test en 5 subpruebas que verifican distintas cualidades de la implementación de WebSocket:

1. **Tolerancia a tipos incorrectos en campos válidos**
    - El objetivo es enviar JSONs bien formados, pero con tipos incorrectos (e.g., números donde se espera un string, etc.).
    - Resultado esperado:
        - El servidor debe rechazar el mensaje o ignorarlo limpiamente.
        - Si responde como si fuera válido, puede haber riesgo de comportamiento impredecible o ejecución no controlada.
    - Payload del fuzzing: `ws_schema_fuzz.txt`
        
        ```json
        null
        12345
        true
        []
        ["unexpected"]
        {}
        {"invalid":"json"}
        {"action":null}
        {"action":123}
        {"action":[]}
        {"action":{"nested":"value"}}
        ```
        
    
    ![image.png](attachment:2f41c9ec-c681-4abf-9915-c61cfe6553c8:image.png)
    
    ![image.png](attachment:1e17af59-35fd-4a61-8dad-f13765e18e8a:image.png)
    
    ![image.png](attachment:e047d259-8091-4ec2-89c1-d449cd718cdb:image.png)
    
    - **Responses:**
        
        ```json
        {"message":"required a JSON object","request":null,"success":false}
        {"message":"required a JSON object","request":12345,"success":false}
        {"message":"required a JSON object","request":true,"success":false}
        {"message":"required a JSON object","request":["unexpected"],"success":false}
        {"message":"required a JSON object","request":[],"success":false}
        {"registered":null,"request":{},"success":false}
        {"registered":null,"request":{"action":null},"success":false}
        {"registered":null,"request":{"invalid":"json"},"success":false}
        {"registered":null,"request":{"action":123},"success":false}
        {"registered":null,"request":{"action":[]},"success":false}
        {"registered":null,"request":{"action":{"nested":"value"}},"success":false}
        ```
        
    
2. **Campos inesperados o campos extra**
    - El objetivo es enviar claves no esperadas o con caracteres raros.
    - Resultado esperado:
        - El servidor debe ignorarlos, rechazarlos o cerrar la conexión con error.
        - Si los procesa, podría haber una vía para la inyección de código.
    - Payload del fuzzing: `ws_extra_fields_fuzz.txt`
        
        ```json
        {"action":"register","__proto__":"exploit"}
        {"action":"register","constructor":"alert(1)"}
        {"action":"register","<script>":"x"}
        {"action":"register","🍕":"pizza"}
        {"action":"register","💣":"boom"}
        {"action":"register","extra_field":"value"}
        {"action":"register","debug":"true"}
        {"action":"register","null":null}
        {"action":"register","undefined":undefined}
        {"action":"register","":"emptykey"}
        ```
        
    
    ![image.png](attachment:c1b43e77-3173-4057-8a54-3b8f2c8a242a:image.png)
    
    ![image.png](attachment:29cc72c0-af39-4b3e-ba2b-ed4717045e1a:image.png)
    
    - **Responses:**
        
        ```json
        {"registered":null,"request":{"__proto__":"exploit","action":"register"},"success":false}
        {"registered":null,"request":{"action":"register","constructor":"alert(1)"},"success":false}
        {"registered":null,"request":{"<script>":"x","action":"register"},"success":false}
        {"registered":null,"request":{"action":"register","🍕":"pizza"},"success":false}
        {"registered":null,"request":{"action":"register","💣":"boom"},"success":false}
        {"registered":null,"request":{"action":"register","extra_field":"value"},"success":false}
        {"registered":null,"request":{"action":"register","debug":"true"},"success":false}
        {"registered":null,"request":{"action":"register","null":null},"success":false}
        {"message":"invalid JSON input","request":null,"success":false}
        {"registered":null,"request":{"":"emptykey","action":"register"},"success":false}
        ```
        
    
3. **Comandos desconocidos o modificados**
    - El objetivo es cambiar un valor de acción (‘action’) válido por otros comandos maliciosos o no válidos que puedan activar comportamientos anómalos en el servidor.
    - Resultado esperado:
        - El servidor debe ignorarlos, rechazarlos o cerrar la conexión con error.
        - Si responde con posibles comandos, estaría exponiendo comandos internos.
    - Payload del fuzzing: `ws_command_fuzz.txt`
        
        ```json
        {"action":"hack"}
        {"action":"DROP TABLE users"}
        {"action":"shutdown"}
        {"action":"unknownCommand"}
        {"action":"reboot"}
        {"event":"99999"}
        {"event":"../etc/passwd"}
        {"action":"😈"}
        {"action":"🚀launch"}
        {"action":"%00"}
        ```
        
    
    ![image.png](attachment:bddf39ef-53fe-49a3-be44-bf3f2e4e19f8:image.png)
    
    ![image.png](attachment:faf458df-a298-463f-a545-66c193032975:image.png)
    
    - **Responses:**
        
        ```json
        {"message":"invalid action","request":{"action":"hack"},"success":false}
        {"message":"invalid action","request":{"action":"unknownCommand"},"success":false}
        {"message":"invalid action","request":{"action":"shutdown"},"success":false}
        {"message":"invalid action","request":{"action":"reboot"},"success":false}
        {"message":"invalid action","request":{"action":"DROP TABLE users"},"success":false}
        {"registered":null,"request":{"event":"../etc/passwd"},"success":false}
        {"registered":null,"request":{"event":"99999"},"success":false}
        {"message":"invalid action","request":{"action":"😈"},"success":false}
        {"message":"invalid action","request":{"action":"🚀launch"},"success":false}
        {"message":"invalid action","request":{"action":"%00"},"success":false}
        ```
        
    
4. **Evasión por formato/*encoding*/duplicados**
    - Se envían codificaciones raras o caracteres escapados que puedan saltarse alguna validación.
    - Resultado esperado:
        - El servidor debe ignorarlos, rechazarlos o cerrar la conexión con error.
        - Si los procesa, podría haber una vía para la inyección de código.
    - Payload del fuzzing: `ws_evasion_fuzz.txt`
        
        ```json
        {"action":"\u0072\u0065\u0067\u0069\u0073\u0074\u0065\u0072"}
        {"action":"\\\"register\\\""}
        {"action":"\\u0000"}
        {"action":"\x00"}
        {"action":"\xFF"}
        {"action":"\\x73\\x74\\x61\\x72\\x74"}
        {"action":"\\\\register"}
        {"action":"//register"}
        {"action":"/*register*/"}
        {"action":"‘ OR 1=1 --"}
        ```
        
    
    ![image.png](attachment:00d8f789-6385-48f1-8fff-fb5357b6b500:image.png)
    
    ![image.png](attachment:bcc3357c-9be4-4d36-ad09-4a5221b892f4:image.png)
    
    - **Responses:**
        
        ```json
        {"registered":null,"request":{"action":"register"},"success":false}
        {"message":"invalid action","request":{"action":"\\\"register\\\""},"success":false}
        {"message":"invalid action","request":{"action":"\\u0000"},"success":false}
        {"message":"invalid JSON input","request":null,"success":false}
        {"message":"invalid JSON input","request":null,"success":false}
        {"message":"invalid action","request":{"action":"\\x73\\x74\\x61\\x72\\x74"},"success":false}
        {"message":"invalid action","request":{"action":"\\\\register"},"success":false}
        {"message":"invalid action","request":{"action":"//register"},"success":false}
        {"message":"invalid action","request":{"action":"/*register*/"},"success":false}
        {"message":"invalid action","request":{"action":"‘ OR 1=1 --"},"success":false}
        ```
        
    
5. **Mensajes muy grandes**
    - El objetivo es enviar mensajes con grandes cantidades de datos para probar si se puede sobrecargar el servicio por tamaño o anidación de campos.
    - Resultado esperado:
        - El servidor debería tener un tamaño límite y cortar si el mensaje se pasa de esa longitud.
        - Si los procesa y responde, o se ralentiza, podría existir una vulnerabilidad DoS por *payload size*.
    - Payload del fuzzing: `ws_dos_fuzz.txt`
        
        ```json
        {"action":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        {"action":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        {"action":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}
        {"action":{"level1":{"level2":{"level3":{"level4":{"level5":"deep"}}}}}}
        {"action":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
        {"action":"💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥"}
        {"event":"eventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventname"}
        {"filters":{"key":"valuevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevalue"}}
        ```
        
    
    ![image.png](attachment:42d139dc-b7ef-4ca3-8012-34f272a103d5:image.png)
    
    ![image.png](attachment:4f21ec76-022c-443e-8719-e6c42a0b3377:image.png)
    
    - **Responses:**
        
        ```json
        {"message":"invalid action","request":{"action":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"success":false}
        {"message":"invalid action","request":{"action":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"success":false}
        {"registered":null,"request":{"action":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]},"success":false}
        {"registered":null,"request":{"action":{"level1":{"level2":{"level3":{"level4":{"level5":"deep"}}}}}},"success":false}
        {"message":"invalid action","request":{"action":"💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥💥"},"success":false}
        {"message":"invalid JSON input","request":null,"success":false}
        {"registered":null,"request":{"event":"eventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventnameeventname"},"success":false}
        {"registered":null,"request":{"filters":{"key":"valuevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevaluevalue"}},"success":false}
        ```
        
    

### 2. Conclusiones

1. **Tolerancia a tipos incorrectos en campos válidos**
    - Todos los mensajes son rechazados (“success”:false).
    - Algunos son rechazados por no tener el formato JSON adecuado, y otros son rechazados porque el valor asociado a una clave válida no está registrado.
    
2. **Campos inesperados o campos extra**
    - El servidor rechaza todos los mensajes de nuevo.
    - En este caso rechaza todos los mensajes por utilizar claves no registradas, a excepción del mensaje que incluye una clave vacía, que lo rechaza por formato JSON inválido.
    
3. **Comandos desconocidos o modificados**
    - El servidor rechaza todos los mensajes de nuevo.
    - Los mensajes en los que se trata de modificar la acción por una inválida son devueltos con un mensaje de “`invalid action`”.
    - Por otra parte, los mensajes que intentan alterar un “event” son rechazados por no estar registrados (`“registered”: null`).
    
4. **Evasión por formato/*encoding*/duplicados**
    - De nuevo, todos los mensajes son rechazados.
    - El servidor vuelve a mostrar errores de acciones inválidas, JSONs inválidos y acciones no registradas.
    
5. **Mensajes muy grandes**
    - Todos los mensajes son rechazados, no obstante, son procesados.
    - Quizás sea que los mensajes no sean lo suficientemente pesados para que el servidor corte y no los procese.
    - Que procesando mensajes tan largos podría llevar a pensar que el servidor pueda ralentizarse o bloquearse si recibe mensajes muy largos y no tiene ningún mecanismo para cortar mensajes tan pesados.

### 3. Conclusiones

En conjunto, las pruebas realizadas con OWASP ZAP sobre el canal WebSocket de Thinger.io muestran que la implementación responde de manera robusta frente a entradas inválidas. Los diferentes escenarios planteados han sido consistentemente rechazados por el servidor. En la mayoría de los casos, Thinger.io devuelve mensajes de error claros, como “`invalid action`” y “`success:false`”, lo que indica que existen mecanismos de validación activos que impiden la ejecución de órdenes malformadas o no registradas.

La única observación relevante se encuentra en el envío de mensajes de gran tamaño: aunque estos también son rechazados, el servidor llega a procesarlos, lo que abre la posibilidad de que volúmenes mucho mayores de datos pudieran afectar a su rendimiento. Aun así, en las condiciones probadas, el sistema no mostró signos de caída ni de bloqueo.

