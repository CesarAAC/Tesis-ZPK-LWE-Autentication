# LWE Authentication Benchmark

Repositorio experimental para comparar, bajo una metodología común y reproducible, seis candidatos de autenticación:

1. `ecdsa` — ECDSA P-256, baseline tradicional.
2. `standard_lwe` — autenticación basada en LWE estándar (**pendiente de implementación**).
3. `binary_lwe` — variante LWE con secreto binario (**pendiente**).
4. `ring_lwe` — variante Ring-LWE (**pendiente**).
5. `lwr` — Learning With Rounding (**pendiente**).
6. `proposed_lwe` — protocolo diseñado en la tesis (**pendiente**).

El objetivo del repositorio no es producir un “ganador” automático. El framework registra evidencia comparable sobre rendimiento, memoria, tamaños serializados, comunicación, almacenamiento, comportamiento proyectado bajo distintas redes, complejidad de implementación y metadatos de reproducibilidad. Las afirmaciones de seguridad, madurez y arquitectura se almacenan aparte y deben incluir evidencia explícita.

> **Regla principal:** una primitiva matemática no se registra como protocolo completo. Un candidato solo queda disponible para benchmarking cuando implementa el ciclo completo de autenticación y supera las pruebas de conformidad comunes.

---

## Estado actual

- ECDSA P-256 es el único candidato completamente implementado.
- Los helpers de generación de claves Standard-LWE y Binary-LWE continúan en `backend/crypto_core/lwe/` como primitivas reutilizables; no son protocolos de autenticación.
- Los otros cuatro candidatos existen en el catálogo con `implementation_factory=None` y fallan de forma cerrada.
- Ya están preparados el contrato común, benchmark runner, pruebas de conformidad, mediciones, exportación JSON/CSV, persistencia PostgreSQL, proyecciones de red y formatos para assessments cualitativos y estimaciones de seguridad.

No se implementa ningún protocolo LWE nuevo en esta etapa.

---

# Estructura del repositorio

```text
lwe-auth-project/
├── backend/
│   ├── api/v1/                  # API HTTP del prototipo
│   ├── benchmarking/            # framework experimental
│   │   ├── configs/
│   │   │   ├── default.json
│   │   │   ├── assessment.template.json
│   │   │   └── security.template.json
│   │   ├── assessment.py
│   │   ├── assessment_cli.py
│   │   ├── cli.py
│   │   ├── code_metrics.py
│   │   ├── config.py
│   │   ├── conformance.py
│   │   ├── environment.py
│   │   ├── export.py
│   │   ├── memory.py
│   │   ├── network.py
│   │   ├── persistence.py
│   │   ├── runner.py
│   │   ├── security.py
│   │   ├── security_cli.py
│   │   ├── serialization.py
│   │   ├── statistics.py
│   │   └── types.py
│   ├── crypto_core/
│   │   ├── interface.py         # contrato obligatorio para todos los protocolos
│   │   ├── registry.py          # catálogo de los seis candidatos
│   │   ├── lwe/                 # primitivas reutilizables; NO protocolos completos
│   │   └── protocols/           # implementaciones completas únicamente
│   └── tests/
├── db/
│   ├── init.sql
│   └── migrations/001_benchmarking.sql
├── scripts/
│   ├── benchmark.sh
│   ├── db-migrate.sh
│   └── test.sh
├── Makefile
└── docker-compose.yml
```

Los resultados generados se escriben en `backend/benchmark-results/` y no se versionan en Git. Las corridas oficiales también pueden persistirse en PostgreSQL.

---

# Inicio rápido

Desde `lwe-auth-project/`:

```bash
cp .env.example .env
docker compose up -d --build
```

Si el volumen de PostgreSQL ya existía antes de añadir el esquema de benchmarking:

```bash
make db-migrate
```

Ejecutar todas las pruebas:

```bash
make test
```

Comprobar la API:

```bash
curl http://localhost:8010/health
curl http://localhost:8010/api/v1/methods
curl http://localhost:8010/api/v1/protocols
```

- `/methods` muestra únicamente protocolos completamente disponibles.
- `/protocols` muestra los seis candidatos y su estado de implementación.

---

# Contrato común de autenticación

Todos los candidatos deben heredar de:

```text
backend/crypto_core/interface.py::AuthProtocol
```

El ciclo observable es el mismo para todos:

```text
Deployment / system setup (una vez por despliegue):
    system_parameters = generate_system_parameters(parameters)

Enrollment (una vez por usuario / rotación de clave):
    (public_key, private_key) = generate_keypair(system_parameters, parameters)

Authentication (cada sesión):
    challenge = generate_challenge(system_parameters, public_key)
    response  = solve_challenge(system_parameters, private_key, challenge)
    valid     = verify_response(system_parameters, public_key, challenge, response)
```

El verificador nunca recibe la clave privada del usuario.

`system_parameters` representa material **público y compartido** generado una vez por despliegue. Ejemplos posibles son una matriz pública común o parámetros algebraicos generados. Si un protocolo no requiere material compartido generado, debe devolver `{}`. Los parámetros criptográficos fijos o configurables siguen registrándose mediante `resolve_parameters()`.

Esta separación evita cargar incorrectamente a cada usuario el costo de estructuras que realmente podrían compartirse entre todos.

## Métodos obligatorios

```python
@property
def name(self) -> str: ...

def default_parameters(self) -> dict: ...

def resolve_parameters(self, overrides: dict | None = None) -> dict: ...

def generate_system_parameters(self, **params) -> dict: ...

def generate_keypair(self, system_parameters: dict, **params): ...

def generate_challenge(self, system_parameters: dict, public_key: dict): ...

def solve_challenge(
    self,
    system_parameters: dict,
    private_key: dict,
    challenge: dict,
): ...

def verify_response(
    self,
    system_parameters: dict,
    public_key: dict,
    challenge: dict,
    response: dict,
) -> bool: ...
```

## Reglas del contrato

### 1. Parámetros efectivos explícitos

`resolve_parameters()` debe devolver **todos** los parámetros criptográficos efectivos, no únicamente los overrides del usuario.

Si el protocolo usa internamente `n`, `m`, `q`, distribución del secreto, distribución/error, `sigma`, polinomio del anillo, módulo de redondeo u otro parámetro relevante, debe aparecer allí.

No aceptar silenciosamente parámetros desconocidos. El benchmark nunca debe registrar un valor y ejecutar otro distinto.

### 2. Serialización

`system_parameters`, claves, challenges y responses deben ser diccionarios compatibles con JSON.

El benchmark utiliza JSON UTF-8 determinista:

- claves ordenadas;
- separadores compactos;
- sin representación Python específica.

Datos binarios deben codificarse explícitamente, por ejemplo en Base64.

### 3. Challenge fresco

Dos challenges consecutivos no deben ser iguales. Una respuesta válida para un challenge no debe verificar bajo otro challenge.

### 4. Binding a la identidad/clave pública

Una respuesta producida para una clave no debe verificar bajo otra clave pública.

### 5. Sin mutación silenciosa

Las operaciones no deben modificar estructuras de entrada como `system_parameters`, clave pública o clave privada.

---

# Cómo implementar un candidato pendiente

Esta sección está pensada para que cualquier integrante del proyecto pueda agregar un protocolo sin tener que modificar el framework de benchmarking.

## Paso 1 — Crear la implementación completa

Crear, por ejemplo:

```text
backend/crypto_core/protocols/ring_lwe.py
```

La clase debe heredar de `AuthProtocol` e implementar **todo** el contrato.

Las operaciones matemáticas auxiliares pueden vivir en otros módulos. El archivo registrado en `protocols/` debe representar el protocolo completo de autenticación.

No registrar nunca una implementación si:

- `verify_response()` es placeholder;
- devuelve `True` incondicionalmente;
- solo implementa keygen;
- no liga la respuesta al challenge;
- no liga la respuesta a la clave pública correspondiente.

## Paso 2 — Decidir qué es setup compartido y qué es material por usuario

Si una estructura es realmente compartida por todo el despliegue, generarla en:

```python
generate_system_parameters(...)
```

Si es diferente para cada usuario, debe formar parte de `public_key` o `private_key`.

Esta decisión afecta directamente:

- costo de setup;
- almacenamiento compartido;
- almacenamiento por usuario;
- comunicación de registro;
- análisis de centralización y arquitectura.

Debe justificarse en el diseño del protocolo.

## Paso 3 — Declarar parámetros efectivos

Implementar:

```python
def default_parameters(self) -> dict:
    ...

def resolve_parameters(self, overrides=None) -> dict:
    ...
```

Los valores usados internamente deben ser exactamente los valores retornados.

## Paso 4 — Registrar la implementación

Abrir:

```text
backend/crypto_core/registry.py
```

Buscar el `ProtocolSpec` correspondiente y reemplazar únicamente:

```python
implementation_factory=None
```

por la clase/factory real.

IDs canónicos del proyecto:

```text
ecdsa
standard_lwe
binary_lwe
ring_lwe
lwr
proposed_lwe
```

No crear aliases nuevos ni un séptimo candidato sin modificar deliberadamente la metodología experimental.

## Paso 5 — Añadir pruebas específicas

Como mínimo probar:

- round-trip válido;
- challenge modificado rechazado;
- respuesta de otra clave rechazada;
- entradas malformadas rechazadas explícitamente;
- parámetros inválidos rechazados;
- estructuras JSON serializables;
- comportamiento correcto de `generate_system_parameters()`;
- inexistencia de mutaciones inesperadas.

Ejecutar:

```bash
make test
```

## Paso 6 — Configurar parámetros experimentales

Editar:

```text
backend/benchmarking/configs/default.json
```

Ejemplo estructural:

```json
{
  "protocol_parameters": {
    "ecdsa": {},
    "ring_lwe": {
      "n": 0,
      "q": 0
    }
  }
}
```

Los `0` anteriores son únicamente ilustrativos. Los parámetros reales deben provenir del diseño y análisis de seguridad.

`target_security_bits` indica el **objetivo** de comparación. No prueba automáticamente que un conjunto de parámetros alcance ese nivel.

---

# Conformance gate

Antes de recopilar métricas, cada implementación pasa automáticamente por pruebas comunes que verifican:

- serialización JSON del setup, claves, challenge y response;
- challenges frescos;
- round-trip válido;
- rechazo de replay sobre otro challenge;
- rechazo de respuesta bajo otra clave pública;
- ausencia de mutación de entradas.

Si falla una sola comprobación, el candidato no debe entrar al benchmark.

Estas pruebas son de consistencia funcional. **No constituyen una prueba formal de seguridad.**

---

# Metodología experimental

El benchmark separa tres costos conceptualmente distintos.

## A. Setup del sistema

Medido independientemente:

- `setup` wall time y CPU time;
- tamaño serializado de `system_parameters`;
- almacenamiento compartido por despliegue;
- tamaño del mensaje canónico necesario para distribuir esos parámetros.

Este costo **no se suma automáticamente a cada usuario ni a cada autenticación**.

## B. Enrollment por usuario

Medido independientemente:

- `keygen` wall time y CPU time;
- tamaño de clave pública;
- tamaño de clave privada;
- almacenamiento persistente del servidor por usuario;
- almacenamiento persistente del cliente por usuario;
- tamaño del registro/transmisión canónica de la clave pública.

## C. Autenticación

Medido por separado:

- `challenge`;
- `response`;
- `verify`;
- flujo completo `authentication`.

El flujo completo genera un challenge nuevo, calcula response y verifica en una sola muestra temporizada.

---

# Métricas automáticas

## Tiempo

Se usa:

- `time.perf_counter_ns()` para tiempo de pared;
- `time.process_time_ns()` para tiempo de CPU del proceso.

Para cada conjunto de muestras se calculan:

- `sample_count`;
- media;
- mediana;
- desviación estándar muestral;
- mínimo;
- P95;
- P99;
- máximo.

Las iteraciones de warm-up se ejecutan antes de medir y no forman parte de los resultados.

Durante la fase de autenticación se precalculan `authentication_key_sets` identidades fuera del temporizador y las iteraciones rotan entre ellas. Así el tiempo de `keygen` permanece separado de `authentication`, pero los resultados no dependen de una única clave concreta.

## Throughput

Se registra una tasa secuencial agregada de autenticación (`auth/s`) calculada como:

```text
N / suma(tiempos de autenticación)
```

No se promedian valores individuales de `1 / latencia`, porque eso produciría una estimación distinta y potencialmente sesgada. Tampoco debe interpretarse como throughput concurrente del servidor HTTP.

## Memoria

La memoria se mide en una fase separada del timing para reducir contaminación.

Para `setup`, `keygen`, `challenge`, `response`, `verify` y `authentication` se registra:

- incremento RSS medio observado;
- incremento RSS pico observado;
- pico de asignaciones Python mediante `tracemalloc`.

Limitación importante:

- RSS incluye memoria nativa pero el muestreo puede omitir picos extremadamente breves;
- `tracemalloc` no observa toda la memoria nativa de Sage/cryptography.

Por ello ambas medidas se conservan y deben interpretarse conjuntamente.

## Tamaño de artefactos

Se mide el tamaño **real serializado** de:

- system parameters;
- clave pública;
- clave privada;
- challenge;
- response.

No se usa únicamente el número teórico de coeficientes.

## Comunicación

Se distinguen tres etapas:

- setup: distribución de parámetros compartidos;
- enrollment: registro de la clave pública;
- autenticación: challenge + response.

Para autenticación se registra:

- challenge message bytes;
- response message bytes;
- bytes totales del sobre criptográfico de aplicación;
- cantidad de mensajes;
- round trips criptográficos.

El sobre canónico incluye:

```json
{
  "type": "...",
  "protocol": "...",
  "payload": {}
}
```

Los resultados **no incluyen** headers HTTP, TLS, TCP/IP, retransmisiones ni congestión. De esta forma la métrica principal depende del protocolo y no de un framework web particular.

## Serialización

Se mide separadamente el costo de serializar y deserializar challenge/response. Ese tiempo no se mezcla con la operación criptográfica pura.

## Almacenamiento

Se registran por separado:

- `shared_deployment/system_parameters`;
- `per_user/server_persistent`;
- `per_user/client_persistent`;
- `per_user/combined_persistent`.

Las extrapolaciones a 1.000, 100.000 o 1.000.000 de usuarios deben calcularse posteriormente a partir de estos datos.

## Indicadores de implementación

Automáticamente se registran, entre otros:

- número de parámetros efectivos;
- dependencias declaradas;
- líneas fuente no vacías/no comentario;
- tamaño del archivo fuente;
- SHA-256 del archivo fuente de la clase registrada.

Son **indicadores**, no un score automático de “facilidad”.

---

# Red: proyección controlada

`backend/benchmarking/configs/default.json` define escenarios sintéticos de RTT y ancho de banda.

Para cada escenario se proyecta aproximadamente:

```text
transport = RTT + bits_serializados / ancho_de_banda
```

y:

```text
E2E proyectado = criptografía medida + serialización medida + transporte proyectado
```

Estas métricas se almacenan explícitamente como `network_projection`.

No equivalen a una medición WAN real y no incluyen:

- establecimiento TCP;
- handshake TLS;
- headers HTTP;
- pérdida de paquetes;
- retransmisiones;
- congestión;
- colas externas.

Si posteriormente se realizan pruebas con `tc/netem`, redes físicas o dispositivos separados, deben registrarse como **otro experimento** y no mezclarse con estas proyecciones.

---

# Reducción de sesgo experimental

La configuración permite:

```json
{
  "warmup_iterations": 20,
  "timing_iterations": 200,
  "authentication_key_sets": 5,
  "memory_iterations": 20,
  "cooldown_seconds_between_protocols": 1.0,
  "randomize_protocol_order": true,
  "protocol_order_seed": 20260930
}
```

Cuando hay varios candidatos:

- el orden puede mezclarse de forma reproducible usando la semilla indicada;
- el orden realmente ejecutado queda almacenado en `protocol_order`;
- existe un cooldown configurable entre protocolos;
- cada candidato hace su propio warm-up;
- timing y memoria se miden por separado.

Para corridas oficiales se recomienda mantener exactamente la misma política para todos los candidatos.

Opcionalmente se puede fijar afinidad de CPU desde el launcher:

```bash
BENCHMARK_CPUSET=2 ./scripts/benchmark.sh
```

No es obligatorio. Si se usa, debe utilizarse la misma política en todas las corridas comparadas. El valor se registra automáticamente.

---

# Metadatos de reproducibilidad

Cada corrida produce automáticamente:

- UUID del experimento;
- UUID de cada protocolo;
- commit Git exacto;
- indicador de working tree limpio/sucio;
- configuración completa;
- SHA-256 canónico de la configuración (`config_sha256`);
- timestamps UTC de inicio y fin;
- orden real de protocolos;
- parámetros criptográficos efectivos;
- conformance checks;
- Python y su implementación;
- SageMath;
- SO/kernel del contenedor;
- arquitectura;
- modelo, núcleos y frecuencia reportada de CPU;
- afinidad efectiva del proceso;
- `nice` del proceso;
- RAM visible y límite del cgroup;
- carga del sistema al inicio;
- versiones de dependencias relevantes;
- inventario de paquetes Python instalados;
- ID de imagen Docker;
- versión de Docker y Compose recibidas desde el launcher;
- `uname` del host;
- CPU set solicitado, si existe;
- muestras crudas;
- estadísticas agregadas.

La aleatoriedad criptográfica **no se sustituye por un PRNG inseguro con semilla fija**. La reproducibilidad se refiere al código, parámetros, entorno y procedimiento, no a reutilizar nonces o claves secretas.

---

# Corridas oficiales y working tree

El launcher oficial es:

```bash
./scripts/benchmark.sh
```

Por defecto rechaza corridas con cambios sin commit dentro del proyecto.

Para una corrida exploratoria deliberada:

```bash
ALLOW_DIRTY_BENCHMARK=1 ./scripts/benchmark.sh --no-db
```

La corrida queda marcada como `git_dirty=true` y no debería utilizarse como evidencia final.

---

# Ejecutar benchmarking

Construir imagen:

```bash
make build
```

Listar candidatos:

```bash
make benchmark-list
```

Ejecutar todos los protocolos disponibles:

```bash
make benchmark
```

Ejecutar únicamente ECDSA:

```bash
./scripts/benchmark.sh --protocol ecdsa
```

Cuando los seis estén implementados:

```bash
./scripts/benchmark.sh \
  --protocol ecdsa \
  --protocol standard_lwe \
  --protocol binary_lwe \
  --protocol ring_lwe \
  --protocol lwr \
  --protocol proposed_lwe
```

Smoke test sin DB:

```bash
ALLOW_DIRTY_BENCHMARK=1 \
./scripts/benchmark.sh --protocol ecdsa --no-db
```

Para resultados oficiales se recomienda PostgreSQL habilitado y working tree limpio.

---

# Archivos de resultados

Cada experimento exporta:

```text
backend/benchmark-results/<experiment-uuid>/
├── experiment.json
├── measurements.csv
└── summaries.csv
```

### `experiment.json`

Manifiesto autocontenido con configuración, fingerprint, entorno, commit, timestamps, orden, parámetros, conformance checks, muestras y summaries.

### `measurements.csv`

Muestras individuales y métricas escalares derivadas.

### `summaries.csv`

Estadísticos agregados listos para análisis, tablas y gráficas.

---

# PostgreSQL

Tablas de benchmarking:

```text
benchmark_experiments
benchmark_protocol_runs
benchmark_measurements
benchmark_summaries
benchmark_protocol_assessments
benchmark_security_assessments
```

Las primeras cuatro conservan evidencia experimental observada.

Las dos últimas conservan información que no debe inventarse automáticamente:

- seguridad estimada;
- ataques;
- restricciones de parámetros;
- madurez;
- interoperabilidad;
- arquitectura de confianza;
- procedimientos operacionales;
- otras conclusiones respaldadas por evidencia.

## Migraciones

En un volumen PostgreSQL nuevo, `db/init.sql` aplica la migración automáticamente.

En un volumen existente:

```bash
make db-migrate
```

La migración es idempotente. No elimine un volumen con datos únicamente para volver a ejecutar `init.sql`.

Las claves privadas no se persisten como parte de los resultados; se conserva únicamente su tamaño serializado como métrica.

---

# Assessments cualitativos con evidencia

Plantilla:

```text
backend/benchmarking/configs/assessment.template.json
```

Cada criterio posee:

- `value`;
- `evidence`.

Dimensiones:

- `implementation`;
- `operational`;
- `trust_architecture`;
- `maturity`;
- `security`.

Los campos comienzan en `null` intencionalmente.

Validar sin escribir en DB:

```bash
docker compose run --rm --no-deps -T benchmark \
  sage -python -m benchmarking.assessment_cli \
  --run-id <RUN_UUID> \
  --file <assessment.json> \
  --validate-only
```

Persistir:

```bash
docker compose run --rm -T benchmark \
  sage -python -m benchmarking.assessment_cli \
  --run-id <RUN_UUID> \
  --file <assessment.json> \
  --source "paper/standard/commit/sección"
```

No convertir automáticamente estos criterios en “fácil/medio/difícil” o en una puntuación global.

---

# Estimaciones de seguridad

Las estimaciones numéricas de seguridad tienen un flujo separado.

Plantilla:

```text
backend/benchmarking/configs/security.template.json
```

Debe registrar:

- protocolo;
- tipo de assessment;
- herramienta, estándar, paper o fuente;
- versión de la herramienta cuando aplique;
- bits de seguridad clásica y/o cuántica;
- supuestos;
- modelo de costo;
- referencia o archivo de salida crudo.

Validar:

```bash
docker compose run --rm --no-deps -T benchmark \
  sage -python -m benchmarking.security_cli \
  --run-id <RUN_UUID> \
  --file <security.json> \
  --validate-only
```

Persistir:

```bash
docker compose run --rm -T benchmark \
  sage -python -m benchmarking.security_cli \
  --run-id <RUN_UUID> \
  --file <security.json>
```

El benchmark **nunca deriva por sí solo bits de seguridad** a partir de `n`, `q` o del nombre del protocolo.

---

# API

Dirección por defecto:

```text
http://localhost:8010
```

Endpoints:

```text
GET  /health
GET  /api/v1/methods
GET  /api/v1/protocols
POST /api/v1/generate_keys
POST /api/v1/challenge
POST /api/v1/solve
POST /api/v1/verify
```

Generar material ECDSA:

```bash
curl -X POST http://localhost:8010/api/v1/generate_keys \
  -H 'Content-Type: application/json' \
  -d '{"protocol_name":"ecdsa","parameters":{}}'
```

La respuesta incluye:

- `system_parameters`;
- `public_key`;
- `private_key`;
- `effective_parameters`.

Para los siguientes pasos, reenviar el mismo `system_parameters` recibido durante enrollment.

`/solve` es un endpoint de desarrollo para ejercitar el prototipo. En un sistema real, la operación que usa la clave privada debe ejecutarse en el cliente/prover que controla el secreto.

Los aliases históricos `standard` y `standard_ecdsa` continúan apuntando a ECDSA, pero nuevos experimentos deben usar `ecdsa`.

---

# Checklist antes de una corrida oficial

1. El protocolo tiene implementación completa, no placeholders.
2. Pasa sus pruebas específicas.
3. Pasa el conformance gate común.
4. Todos los parámetros efectivos quedan registrados.
5. La decisión entre setup compartido y estado por usuario está justificada.
6. El código está committeado.
7. El working tree está limpio.
8. Todos los candidatos usan la misma imagen/entorno experimental.
9. Se usa la misma configuración de benchmark.
10. Se conserva el mismo objetivo de seguridad y luego se verifica con evidencia externa.
11. Setup, enrollment y autenticación se reportan por separado.
12. Timing y memoria se miden en fases separadas.
13. Se conservan muestras crudas.
14. Los tamaños corresponden a bytes serializados reales.
15. Las proyecciones de red se identifican como proyecciones.
16. Las pruebas reales de red, si se hacen, se reportan aparte.
17. Las estimaciones de seguridad conservan herramienta/fuente, versión y supuestos.
18. Las métricas cualitativas conservan evidencia.
19. No se modifica la metodología para favorecer a un candidato después de observar resultados.
20. El commit y `config_sha256` utilizados en la tesis quedan registrados.

Estas reglas tienen prioridad sobre obtener resultados favorables para cualquiera de los seis candidatos.
