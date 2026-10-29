# Documentación del código

Proyecto `lwe-auth-project/`: implementación de los seis candidatos de autenticación de la tesis, el protocolo propuesto ML-ZKAuth y el *framework* con el que se comparan.

Este documento describe el código en el *commit* `05a59f7` (15 de octubre de 2026), el mismo con el que se ejecutó la corrida oficial de la tesis; desde entonces el código del proyecto no ha cambiado. Explica cómo está organizado el repositorio, qué hace cada módulo, cómo funciona cada protocolo, cómo se prueba y cómo se obtienen las métricas. Complementa a otros dos documentos, a los que remite en lugar de repetirlos:

- [`README.md`](../README.md): contrato común, reglas metodológicas, uso del benchmark y la tabla de lecturas que hubo que fijar en ML-ZKAuth.
- [`docs/estimacion-de-dureza.md`](estimacion-de-dureza.md): procedimiento completo de la estimación de dureza con el *lattice-estimator*.

En la tesis, el capítulo 3 (`Document/capitulos/04-Protocolo Propio.tex`) describe ML-ZKAuth y el capítulo 4 (archivos `05` a `09`) presenta la evaluación.

## Contenido

1. [Visión general](#1-visión-general)
2. [Organización del repositorio y entorno de ejecución](#2-organización-del-repositorio-y-entorno-de-ejecución)
3. [Núcleo criptográfico (`crypto_core`)](#3-núcleo-criptográfico-crypto_core)
4. [Protocolos](#4-protocolos)
5. [API HTTP](#5-api-http)
6. [Framework de benchmarking](#6-framework-de-benchmarking)
7. [Estimación de la dureza](#7-estimación-de-la-dureza)
8. [Pruebas](#8-pruebas)
9. [De los resultados a las cifras de la tesis](#9-de-los-resultados-a-las-cifras-de-la-tesis)
10. [Mantenimiento y extensión](#10-mantenimiento-y-extensión)
11. [Limitaciones y observaciones conocidas](#11-limitaciones-y-observaciones-conocidas)
- [Anexo A. Notación](#anexo-a-notación)
- [Anexo B. Formato y tamaño de los artefactos](#anexo-b-formato-y-tamaño-de-los-artefactos)

---

## 1. Visión general

El código tiene tres partes:

1. **`backend/crypto_core/`**: los seis candidatos, todos detrás de un mismo contrato (`AuthProtocol`), y las primitivas en que se apoyan.
2. **`backend/benchmarking/`**: mide a todos los candidatos con el mismo procedimiento y exporta los resultados (JSON y CSV, y opcionalmente PostgreSQL). Por separado, estima la dureza con el *lattice-estimator* y registra evaluaciones cualitativas con evidencia.
3. **`backend/api/`**: una API HTTP (FastAPI) que expone el mismo contrato para ejercitar el prototipo.

```text
   api/ (FastAPI, puerto 8010)              benchmarking/ (CLI, runner, estimación)
              │                                          │
              └──────────────┬───────────────────────────┘
                             ▼
          crypto_core/registry.py  ──►  crypto_core/interface.py (AuthProtocol)
                             │
       ┌─────────────────────┼──────────────────────────────────────────┐
       ▼                     ▼                                          ▼
 protocols/ecdsa.py   protocols/lattice_zk.py (plantilla)        protocols/proposed_lwe.py
                         ├── matrix_lwe_zk.py                           │
                         │     ├── lwe_zk.py  (standard_lwe,            ├── token_hiding.py
                         │     │               binary_lwe)              │   (ML-KEM-768 + AES-GCM)
                         │     └── lwr_auth.py (lwr)                    │
                         └── ring_lwe.py (ring_lwe)                     │
                             │                                          │
                             └──────────────┬───────────────────────────┘
                                            ▼
              crypto_core/lwe/: sampling, codec, ring, module, decomposition, lwr, reconciliation
              NumPy (aritmética) · secrets (aleatoriedad) · hashlib (SHA3-256, SHAKE)
              cryptography/OpenSSL (P-256, ML-KEM-768, AES-256-GCM)
```

### Los seis candidatos

| ID canónico | Clase | Archivo | Supuesto de seguridad | Mecanismo de autenticación |
|---|---|---|---|---|
| `ecdsa` | `StandardECDSAProtocol` | `protocols/ecdsa.py` | Logaritmo discreto en P-256 | Firma ECDSA del reto |
| `standard_lwe` | `StandardLWEProtocol` | `protocols/lwe_zk.py` | LWE, secreto binomial centrado | Fiat–Shamir con abortos (plantilla común) |
| `binary_lwe` | `BinaryLWEProtocol` | `protocols/lwe_zk.py` | LWE, secreto binario | Fiat–Shamir con abortos (plantilla común) |
| `ring_lwe` | `RingLWEProtocol` | `protocols/ring_lwe.py` | Ring-LWE en `Z_q[x]/(xⁿ+1)` | Fiat–Shamir con abortos (plantilla común) |
| `lwr` | `LWRProtocol` | `protocols/lwr_auth.py` | Learning With Rounding | Fiat–Shamir con abortos (plantilla común) |
| `proposed_lwe` | `ProposedLWEAuthProtocol` | `protocols/proposed_lwe.py` | MLWE y SelfTargetMSIS (prueba); ML-KEM-768 y AES-256-GCM (token) | ML-ZKAuth: Fiat–Shamir con abortos al estilo Dilithium, token oculto, tickets de un solo uso y acuerdo de clave opcional |

Todos siguen el mismo ciclo de vida: configuración del despliegue, registro de cada usuario y, en cada sesión, reto, respuesta y verificación (sección 3.1).

---

## 2. Organización del repositorio y entorno de ejecución

### Árbol de archivos

```text
lwe-auth-project/
├── .env.example                 variables de entorno de ejemplo (copiar a .env)
├── Makefile                     atajos: up, build, test, benchmark, db-migrate…
├── README.md                    contrato, metodología, uso
├── docker-compose.yml           servicios db, api y benchmark
├── db/
│   ├── init.sql                 esquema inicial (se ejecuta al crear el volumen)
│   └── migrations/001_benchmarking.sql   tablas del benchmark (idempotente)
├── docs/
│   ├── documentacion-del-codigo.md       este documento
│   └── estimacion-de-dureza.md           estimación de dureza
├── scripts/
│   ├── benchmark.sh             lanzador oficial del benchmark
│   ├── db-migrate.sh            aplica la migración a un volumen existente
│   ├── proof-layer-search.sh    reproduce la búsqueda de (k', η') de ML-ZKAuth
│   └── test.sh                  ejecuta toda la batería de pruebas
└── backend/
    ├── Dockerfile               imagen SageMath + dependencias
    ├── requirements.txt
    ├── main.py                  aplicación FastAPI
    ├── api/v1/                  auth.py (rutas) y schemas.py (modelos)
    ├── crypto_core/
    │   ├── interface.py         contrato AuthProtocol
    │   ├── exceptions.py        jerarquía de excepciones
    │   ├── registry.py          catálogo de los seis candidatos
    │   ├── token_hiding.py      ML-KEM-768 + AES-256-GCM
    │   ├── lwe/                 primitivas (no son protocolos)
    │   └── protocols/           implementaciones completas
    ├── benchmarking/            runner, métricas, exportación, estimación
    │   └── configs/             default.json y plantillas de assessments
    ├── tests/                   18 módulos de pruebas (unittest)
    └── benchmark-results/       resultados generados (no versionado)
```

### Entorno de ejecución

Todo se ejecuta en Docker. La imagen se construye desde `sagemath/sagemath:latest` (`backend/Dockerfile`), corre como el usuario `sage` e instala `requirements.txt` con `sage -pip`; Python se invoca como `sage -python`.

| Servicio (`docker-compose.yml`) | Imagen | Función |
|---|---|---|
| `db` | `postgres:15-alpine` | PostgreSQL; puerto del anfitrión `${POSTGRES_HOST_PORT:-5437}`; ejecuta `db/init.sql` al crear el volumen. |
| `api` | `${API_IMAGE_NAME:-lwe-auth-project-api:local}` | API en `${API_PORT:-8010}` (`uvicorn main:app`). |
| `benchmark` | la misma imagen | Perfil `tools`: contenedor efímero para pruebas, benchmark y estimación (`docker compose run`). |

Los servicios `api` y `benchmark` montan `./backend` en `/app`. Por eso las pruebas y el benchmark siempre ejecutan el código del árbol de trabajo, no una copia congelada en la imagen. El `.dockerignore` excluye `tests/` de la imagen, pero el montaje lo vuelve a hacer visible.

### Dependencias

| Paquete | Uso |
|---|---|
| `numpy` | Aritmética de todos los candidatos de retículos (nunca su generador aleatorio). |
| `cryptography` (con OpenSSL) | ECDSA P-256, ML-KEM-768 y AES-256-GCM. |
| `fastapi`, `uvicorn`, `pydantic` | API HTTP; validación de la configuración del benchmark y de los assessments. |
| `psutil` | Memoria residente (RSS) y metadatos del entorno. |
| `psycopg[binary]` | Persistencia en PostgreSQL (opcional). |
| SageMath (imagen base) | Entorno de Python; lo usan `lwe/keygen.py` (heredado, sin uso), `environment.py` (versión), `hardness.py` (aritmética real del estimador) y una prueba que contrasta la aritmética de anillos. |

La aleatoriedad criptográfica viene siempre de `secrets` (el generador del sistema operativo) o de OpenSSL. SHA3-256 y SHAKE vienen de `hashlib`.

### Atajos (`Makefile`) y scripts

| Comando | Qué hace |
|---|---|
| `make up` | `docker compose up -d --build`: base de datos y API. |
| `make build` | Reconstruye la imagen de la API sin caché. |
| `make test` | `scripts/test.sh`: `unittest discover -s tests -v` dentro del contenedor `benchmark`. |
| `make db-migrate` | Levanta `db` y aplica `001_benchmarking.sql` (idempotente). |
| `make benchmark` | `scripts/benchmark.sh`: corrida oficial (rechaza un árbol de trabajo con cambios). |
| `make benchmark-list` | Lista el catálogo de protocolos. |
| `make proof-layer-search` | `scripts/proof-layer-search.sh`: búsqueda de `(k', η')` de ML-ZKAuth. |
| `make down` | Detiene los servicios. |

Las variables de `.env.example` son los puertos, las credenciales de PostgreSQL y `DATABASE_URL`, `ALLOW_DIRTY_BENCHMARK` (permite una corrida exploratoria con cambios sin *commit*) y `BENCHMARK_CPUSET` (fija la corrida a núcleos concretos).

---

## 3. Núcleo criptográfico (`crypto_core`)

### 3.1 El contrato `AuthProtocol` (`interface.py`)

Todos los candidatos heredan de `AuthProtocol` e implementan los mismos métodos. Los artefactos (`SerializedData`) son diccionarios compatibles con JSON; los datos binarios viajan en Base64.

| Método | Lo ejecuta | Devuelve | Notas |
|---|---|---|---|
| `name` | — | ID interno | Propiedad. |
| `default_parameters()` | — | Parámetros efectivos por defecto | Todos, no solo los ajustables. |
| `resolve_parameters(overrides)` | API, benchmark | Conjunto efectivo completo | Rechaza claves desconocidas y cambios a valores fijos. |
| `generate_system_parameters(**params)` | Despliegue, una vez | Material público compartido | `{}` si el protocolo no lo necesita. Se mide aparte del registro. |
| `generate_keypair(system_parameters, **params)` | Cliente, al registrarse | `(public_key, private_key)` | Debe usar los mismos parámetros del *setup*. |
| `generate_challenge(system_parameters, public_key)` | Verificador | Reto nuevo | Debe ser fresco: dos retos seguidos no coinciden. |
| `solve_challenge(system_parameters, private_key, challenge)` | Cliente (probador) | Respuesta | Única operación que usa la clave privada. |
| `verify_response(system_parameters, public_key, challenge, response)` | Verificador | `bool` | Nunca ve la clave privada. |

Reglas que todo candidato cumple; la verificación de conformidad (sección 6.4) comprueba las reglas 2 a 4, y las pruebas de cada candidato, la 1:

1. `resolve_parameters` devuelve **todos** los parámetros efectivos (dimensiones, módulos, distribuciones, codificaciones…), y el benchmark registra exactamente esos valores.
2. Todo artefacto es serializable en JSON y no se modifica ninguna entrada.
3. Los retos son frescos y una respuesta no verifica con otro reto.
4. Una respuesta no verifica con otra clave pública.

**Excepciones** (`exceptions.py`):

| Excepción | Cuándo | Código HTTP en la API |
|---|---|---|
| `CryptoCoreError` | Base de todas; también, por ejemplo, un probador que agota sus intentos. | 500 (no se captura) |
| `InvalidProtocolDataError` | Entrada mal formada, parámetros inválidos, Base64 inválido, tamaños incorrectos, coeficientes fuera de rango. | 400 |
| `UnknownProtocolError` | ID que no existe en el registro. | 404 |
| `ProtocolUnavailableError` | Entrada del catálogo sin implementación. | 501 |

Una respuesta bien formada pero inválida no lanza excepción: `verify_response` devuelve `False`.

### 3.2 El registro (`registry.py`)

`registry.py` es la única fuente de verdad sobre los candidatos. Cada uno es un `ProtocolSpec` con su ID canónico, nombre, familia, alias, dependencias declaradas, *factory* de la implementación y una nota. Si `implementation_factory` fuera `None`, `require_implementation()` lanzaría `ProtocolUnavailableError`: un candidato sin implementación falla de forma cerrada. Hoy los seis están implementados.

| ID | Alias aceptados |
|---|---|
| `ecdsa` | `standard`, `standard_ecdsa` |
| `standard_lwe` | `lwe` |
| `binary_lwe` | — |
| `ring_lwe` | — |
| `lwr` | `lwrounding`, `lwr_auth` |
| `proposed_lwe` | `custom_lwe` |

`get_protocol(nombre)` normaliza el nombre (minúsculas, sin espacios), resuelve el alias y crea **un objeto nuevo en cada llamada**. Por eso el verificador de ML-ZKAuth no puede guardar su estado en el objeto y usa un almacén del proceso (sección 4.5.6).

### 3.3 Primitivas (`crypto_core/lwe/`)

Son bloques reutilizables; ninguno es un protocolo de autenticación por sí solo.

**`sampling.py`**: muestreadores. Todo valor aleatorio sale de `secrets.token_bytes`; NumPy solo vectoriza.

| Función | Qué hace | La usan |
|---|---|---|
| `sample_uniform_mod_q(shape, q)` | Uniforme en `[0, q)`. Rechazo sobre palabras de 32 bits, sin sesgo de módulo; enmascarado directo si `q` es potencia de 2 ≤ 2¹⁶. | Matriz `A`, polinomio `a`, máscaras. |
| `sample_uniform_box(shape, b)` | Uniforme en `[−b, b]`. | Máscaras de las pruebas. |
| `sample_centered_binomial(shape, η)` | CBD(η): suma de η bits menos suma de η bits. | Secretos y errores. |
| `sample_binary(shape)` | Uniforme en `{0, 1}`. | Secreto de `binary_lwe`. |
| `derive_sparse_ternary(semilla, n, κ)` | Vector en `{−1, 0, 1}ⁿ` con exactamente κ entradas no nulas, derivado de SHAKE-256 como `SampleInBall` de Dilithium: primero κ bits de signo, luego posiciones de 16 bits con rechazo (Fisher–Yates). | Desafío de todas las pruebas de retículos. |
| `derive_centered_binomial`, `sample_discrete_gaussian`, `derive_binary_matrix` | CBD desde semilla, gaussiana discreta por tabla CDT (sin tiempo constante) y matriz binaria desde semilla. | Ningún candidato actual. |

**`codec.py`**: codificación de coeficientes dentro de JSON. Toda decodificación valida el tamaño exacto y el rango, y lanza `InvalidProtocolDataError` si no se cumplen.

| Familia | Funciones | Formato | La usan |
|---|---|---|---|
| Base64 | `decode_base64` (con `validate=True`), `encode_bytes`, `decode_fixed_bytes` | Bytes en Base64; longitud exacta. | Todos. |
| Ancho mínimo | `width_for_range`, `encode_unsigned` / `decode_unsigned`, `encode_signed` / `decode_signed` | 1, 2 o 4 bytes por coeficiente, *little-endian*. Los valores con signo se guardan como `valor + cota`, así que decodificar rechaza todo coeficiente con `\|x\| > cota`: **esa es la comprobación de norma** de las respuestas. | `standard_lwe`, `binary_lwe`, `lwr`, `ring_lwe`. |
| Vector de bits | `encode_bits` / `decode_bits` | 8 bits por byte; rechaza relleno distinto de cero. | Secreto de `binary_lwe`. |
| Empaquetado de bits | `packed_bits`, `packed_length`, `pack_coefficients` / `unpack_coefficients`, `encode_packed` / `decode_packed` | `⌈log₂ módulo⌉` bits por coeficiente (12 para q = 3329, 23 para q′, 18 para `z`). Rechaza longitud incorrecta, relleno distinto de cero y valores fuera de rango. | `proposed_lwe`. |
| `uint16` | `encode_coefficients`, `decode_coefficients` | 2 bytes por coeficiente. | Ningún candidato actual. |

**Aritmética y transformaciones**:

| Módulo | Funciones | Qué hace |
|---|---|---|
| `ring.py` | `negacyclic_multiply(a, b, q)` | Producto en `Z_q[x]/(xⁿ+1)`: convolución de NumPy y plegado `xⁿ = −1`. Complejidad `O(n²)`, sin NTT. |
| `module.py` | `expand_uniform_matrix`, `matrix_vector`, `scale_vector`, `inner_product`, `transpose`, `centered` | Aritmética de módulos sobre `R_q`. `expand_uniform_matrix(semilla, filas, columnas, d, q)` lee, para cada entrada `(i, j)`, el flujo SHAKE-128 de `semilla ‖ i ‖ j` en palabras de 2 o 3 bytes, recortadas a `⌈log₂ q⌉` bits, y descarta las que no son menores que `q`, de modo que los coeficientes son exactamente uniformes. El formato de bytes es propio de este proyecto: no es `SampleNTT` de Kyber ni `ExpandA` de Dilithium. |
| `decomposition.py` | `decompose`, `high_bits`, `low_bits`, `high_values` | `Decompose` de Dilithium: `r = r₁·α + r₀` con `r₀ ∈ (−α/2, α/2]`, para α par que divide a `q − 1`; el intervalo superior se pliega sobre `r₁ = 0`. Con α = 2γ₂ = 190 464 y q′ = 8 380 417 hay 44 valores altos. |
| `lwr.py` | `round_q_to_p(x, q, p)` | Redondeo al más cercano: `⌊(p·x + q/2)/q⌋ mod p`. |
| `reconciliation.py` | `modular_round`, `cross_round`, `reconcile`, `bits_to_bytes`, `bytes_to_bits` | Reconciliación de Peikert coeficiente a coeficiente: bit de clave `⌊2v/q⌉ mod 2`, pista `⌊4v/q⌋ mod 2` y función `rec`. Se aplica sobre el módulo impar 3329 sin la duplicación aleatoria de Peikert: el acuerdo está garantizado si `\|w − v\| ≤ 415`, y el bit tiene un sesgo pequeño (1665 de 3329 residuos dan 0). Ambos hechos se comprueban de forma exhaustiva en las pruebas. |
| `keygen.py` | `generate_standard_lwe_keypair`, `generate_binary_lwe_keypair`, `LWEParameters` | Generadores heredados basados en SageMath. Se cargan de forma perezosa (`lwe/__init__.py`) para no pagar la importación de Sage. **Ningún candidato los usa**, y usan el generador de Sage, no el del sistema operativo, así que no deben usarse en un protocolo. |

### 3.4 Ocultación del token (`token_hiding.py`)

Envuelve ML-KEM-768 y AES-256-GCM de la biblioteca `cryptography` para el token de ML-ZKAuth:

```text
tok1 = texto cifrado de ML-KEM-768 (1088 bytes); K = secreto encapsulado (32 bytes)
tok2 = nonce (12 bytes) ‖ AES-256-GCM_K(contenido, datos asociados)   (+16 bytes de etiqueta)
```

| Función | Qué hace |
|---|---|
| `generate_verifier_keypair()` | Par ML-KEM-768: `vpk` de 1184 bytes y la semilla privada de 64 bytes, que es toda la clave privada. |
| `seal` / `seal_with_secret` | Encapsula hacia `vpk` y cifra el contenido con `K`; la segunda devuelve también `K`. |
| `open_token` / `open_token_with_secret` | Desencapsula y descifra. Devuelve `None` si la etiqueta no verifica: un `tok1` alterado desencapsula a otro secreto (rechazo implícito de ML-KEM) y la etiqueta falla. |
| `seal_symmetric` / `open_symmetric` | AES-256-GCM con *nonce* aleatorio de 96 bits, para la respuesta cifrada del servidor. |

El manuscrito original escribía `tok1 = Kyber.Enc(vpk, K)` con una `K` elegida por el cliente. Un KEM estándar no recibe la clave, sino que la devuelve: aquí `K` es el secreto encapsulado (lectura 8 del README).

---

## 4. Protocolos

### 4.1 ECDSA (`ecdsa.py`)

Es la línea base clásica. Usa la biblioteca `cryptography`, que ejecuta código compilado de OpenSSL.

| Paso | Implementación |
|---|---|
| Parámetros | Fijos: `curve = secp256r1`, `hash = sha256`, `challenge_bytes = 32`. Cualquier otro valor se rechaza. |
| Configuración | Devuelve `{}`; las demás operaciones exigen `system_parameters == {}`. |
| Registro | `ec.generate_private_key(SECP256R1)`. Clave pública `{"key_pem"}`: PEM SubjectPublicKeyInfo en Base64. Clave privada `{"key_pem"}`: PEM PKCS#8 sin cifrar, en Base64. |
| Reto | `{"nonce"}`: 32 bytes de `secrets.token_bytes`, en Base64. |
| Respuesta | `{"signature"}`: firma DER `ECDSA(SHA-256)` del *nonce*. El número `k` de cada firma lo genera OpenSSL al azar (ECDSA no determinista). |
| Verificación | `public_key.verify(firma, nonce, ECDSA(SHA-256))`; `False` si la firma no es válida. |

La firma liga la respuesta al reto. En un despliegue, el verificador debe aceptar cada *nonce* una sola vez; el prototipo no guarda los retos emitidos, porque el contrato le entrega el reto al verificador en cada llamada.

### 4.2 Plantilla Fiat–Shamir con abortos (`lattice_zk.py`)

`standard_lwe`, `binary_lwe`, `lwr` y `ring_lwe` ejecutan el mismo sistema de prueba: la identificación *Fiat–Shamir con abortos* de Lyubashevsky (2012) en su variante LWE, en la que se envían `z₁` y `z₂`. **No es Dilithium:** no usa la descomposición en bits altos y bajos, ni pistas, ni la segunda condición de rechazo, ni la clave pública comprimida; solo los tamaños de parámetros siguen a Dilithium2. Los cuatro candidatos difieren únicamente en la relación lineal que respalda la clave, de modo que las diferencias medidas se atribuyen al supuesto.

**Relación.** Público: el mapa compartido `A` (matriz o elemento del anillo) y la clave `B̃` con `A·S + E = B̃ (mod q)`. Testigo del probador: `S` y `E` cortos.

**Protocolo** (`solve_challenge` y `verify_response`):

```text
Verificador:  nonce ← 32 bytes aleatorios
Probador:     repetir (como máximo 1000 intentos):
                  y₁, y₂ ← uniforme en [−γ, γ]                          (máscaras)
                  w  = A·y₁ + y₂ mod q                                  (compromiso)
                  c̃  = H(dominio, "challenge", id, H(params), H(pk), nonce, w)
                  c  = SparseTernary(c̃): peso κ, derivado con SHAKE-256
                  z₁ = y₁ + S·c,   z₂ = y₂ + E·c
              hasta que ‖z₁‖∞ ≤ γ − β₁ y ‖z₂‖∞ ≤ γ − β₂      (βᵢ = κ·‖testigoᵢ‖∞)
              respuesta = (c̃, z₁, z₂)
Verificador:  decodificar z₁ y z₂ (la decodificación rechaza normas mayores que la cota)
              w′ = A·z₁ + z₂ − B̃·c mod q
              aceptar si H(dominio, "challenge", id, H(params), H(pk), nonce, w′) = c̃
```

`H` es SHA3-256 sobre campos con prefijo de longitud (concatenación sin ambigüedad), con el dominio `lwe-auth/fiat-shamir-with-aborts/v1`. `H(params)` resume el JSON canónico de los parámetros efectivos y `H(pk)` la clave pública codificada. El registro guarda `H(pk)` en la clave privada (`public_key_digest`), así que el probador no necesita la clave pública. La comparación final usa `hmac.compare_digest`. Si el probador agota sus 1000 intentos lanza `CryptoCoreError`; con los parámetros en uso, la probabilidad de que ocurra es despreciable.

**Ganchos que define cada candidato.** La clase base implementa el ciclo completo; las subclases solo definen la relación:

| Gancho | Significado |
|---|---|
| `_fixed_parameters`, `_resolve_tunable` | Parámetros fijos y ajustables (con su validación). |
| `_generate_shared`, `_load_shared` | Material compartido del despliegue (`matrix_a` o `a`). |
| `_generate_user_keys`, `_load_public_key`, `_load_witness` | Claves y su decodificación. |
| `_response_layout` | Componentes de la respuesta: nombre, forma, γ y β. |
| `_challenge_shape` | Longitud y peso del desafío. |
| `_commit`, `_witness_times_challenge`, `_reconstruct_commitment` | `A·y`, `(S·c, E·c)` y `A·z − B̃·c`. |

**Parámetros.** `resolve_parameters` rechaza claves desconocidas y cambios a valores fijos, y valida los ajustables con `validate_proof_parameters`:

- el peso κ está entre 1 y la longitud del desafío;
- el espacio de desafíos tiene al menos 2¹²⁸ elementos;
- `16·γ ≤ q` (el compromiso no debe acercarse al módulo, por la solidez);
- `β < γ` en cada componente (si no, la máscara no ocultaría el secreto);
- la probabilidad de aceptación por intento, `∏ᵢ ((2(γ − βᵢ) + 1)/(2γ + 1))^dimᵢ`, es al menos 0.05.

Además, los `system_parameters` deben traer el ID del protocolo y el conjunto efectivo completo y canónico: `resolve_parameters(parámetros) == parámetros`.

Parámetros fijos comunes (`common_fixed_parameters`): `proof_system = fiat_shamir_with_aborts`, `challenge_distribution = sparse_ternary_shake256`, `masking_distribution = uniform_box`, `nonce_bytes = 32`, `hash = sha3-256`, `xof = shake256` y `coefficient_encoding = minimal_width_le_base64`.

Con los parámetros de `default.json`, cada candidato queda así:

| Candidato | Componentes (dimensión, β) | Aceptación por intento | Intentos medios | Espacio de desafíos |
|---|---|---|---|---|
| `standard_lwe` | (1116, 62), (1116, 62) | 0.348 | 2.9 | 2^129.6 (ℓ = 128, κ = 31) |
| `binary_lwe` | (1196, 31), (1196, 62) | 0.428 | 2.3 | 2^129.6 |
| `lwr` | (1112, 62), (1112, 62) | 0.349 | 2.9 | 2^129.6 |
| `ring_lwe` | (1024, 96), (1024, 96) | 0.223 | 4.5 | 2^131.6 (n = 1024, κ = 16) |

**Propiedades, enunciadas con precisión** (el *docstring* del módulo es la referencia):

- El protocolo interactivo subyacente es de conocimiento cero de verificador honesto especial sin abortos; su versión Fiat–Shamir es una **NIZK en el modelo de oráculo aleatorio programable**. El simulador elige `c̃`, deriva `c`, muestrea `z` uniforme en `[−(γ − β), γ − β]`, fija `w = A·z₁ + z₂ − B̃·c` y programa el oráculo. Coincide con las transcripciones reales porque `‖testigo·c‖∞ ≤ β`: un `z` aceptado es uniforme en esa caja sea cual sea el testigo, y la probabilidad de aceptación no depende de él. Los intentos abortados nunca se envían.
- Es un **argumento de conocimiento de una relación relajada**, no de `(S, E)`: dos transcripciones aceptadas con el mismo `w` y desafíos distintos dan vectores cortos con `A·(z₁ − z₁′) + (z₂ − z₂′) = B̃·(c − c′)`. La resistencia a la suplantación descansa en que la clave sea pseudoaleatoria (LWE, Ring-LWE o LWR) y en la dificultad de SIS sobre `[A | I | −B̃]`; ambas se estiman (sección 7).
- El *nonce* y `H(pk)` entran en el hash: una respuesta no verifica con otro reto ni con otra clave.
- La prueba es transferible (no negable).
- **No analizado:** el modelo de oráculo aleatorio cuántico (QROM) y los canales laterales de tiempo.

### 4.3 Candidatos de matriz (`matrix_lwe_zk.py`, `lwe_zk.py`, `lwr_auth.py`)

La relación es `A·S + E = B̃ (mod q)` con `A ∈ Z_q^{m×n}` compartida, `S` de `n×ℓ` y `E` de `m×ℓ`. La clave tiene **ℓ columnas secretas** (Bai–Galbraith 2014): un solo desafío ternario `c ∈ {−1, 0, 1}^ℓ` de peso κ combina las columnas, de modo que `S·c` y `E·c` son vectores y el espacio de desafíos supera 2¹²⁸ en una sola ronda. Con una sola columna harían falta unas 128 repeticiones.

| Operación | Implementación (`MatrixLWEZKProtocol`) |
|---|---|
| Configuración | `A` uniforme (`sample_uniform_mod_q`), en `system_parameters["matrix_a"]` con 4 bytes por coeficiente. Se genera al azar y se transmite completa: de 6.6 a 7.6 MB en JSON. |
| Registro | El candidato muestrea `S`; `A·S` se calcula en `float64` con BLAS, que es exacto porque `n·(q − 1)·‖S‖∞ < 2⁵³` para todo juego aceptado, y se reduce mod `q`. Clave pública `{"B"}`; privada `{"S", "E", "public_key_digest"}`. |
| Compromiso | `w = A·y₁ + y₂ mod q` (enteros de 64 bits), con `y₁` de dimensión `n` e `y₂` de dimensión `m`. |
| Verificación | `w′ = A·z₁ + z₂ − B̃·c mod q`. |

Ajustables y rangos (`resolve_matrix_dimensions`): `n, m ∈ [16, 4096]`, `q ∈ [2¹⁰, 2²⁴]`, `ℓ ∈ [16, 1024]`, `κ ∈ [1, ℓ]`, `γ ≥ 2`, `η ∈ [1, 8]` y `m·n ≤ 2²⁴` coeficientes. Las clases traen sus propios valores por defecto (`n = m = 1024`, `p = 2²⁰`); el benchmark usa los de `default.json` (sección 6.1).

Cada operación decodifica la matriz `A` desde el JSON de `system_parameters`, y ese costo está incluido en los tiempos y en la memoria medidos: decodificar `A` de 1116×1116 a enteros de 64 bits ocupa unos 10 MB.

- **`standard_lwe`**: `S` y `E` binomiales centrados CBD(η); `B = A·S + E mod q`. LWE en forma normal: el secreto debe ser corto para poder enmascararlo.
- **`binary_lwe`**: `S ∈ {0, 1}^{n×ℓ}`, empaquetado a 1 bit; `E` CBD(η). La cota del secreto es 1, de modo que `β₁ = κ`.
- **`lwr`**: no muestrea error. `B = ⌊(p/q)·A·S⌉ mod p`, con `q` y `p` potencias de 2, `4 ≤ p ≤ q/2`. El error determinista `E = (q/p)·B − A·S`, centrado mod `q`, cumple `‖E‖∞ ≤ q/(2p)` y la prueba corre sobre `B̃ = (q/p)·B`. La clave se transmite mod `p`. El conocimiento cero solo necesita la cota de `E`, no su distribución. La clave es una instancia **LWR**, no LWE; estimarla como LWE con error uniforme es una heurística (sección 7).

### 4.4 Ring-LWE (`ring_lwe.py`)

Anillo `R_q = Z_q[x]/(xⁿ+1)` con `n` potencia de 2 en `[64, 4096]`.

| Operación | Implementación |
|---|---|
| Configuración | `a ∈ R_q` uniforme, en `system_parameters["a"]`. |
| Registro | `s, e ← CBD(η)`, `b = a·s + e`. Clave pública `{"b"}`; privada `{"s", "e", "public_key_digest"}`. |
| Desafío | Un polinomio con κ coeficientes `±1` (estilo `SampleInBall`): con `n = 1024` y κ = 16 el espacio es de 2^131.6, sin columnas secretas. |
| Respuesta | `z₁ = y₁ + c·s`, `z₂ = y₂ + c·e`. Los productos se centran mod `q` para recuperar los enteros exactos, válido porque `κ·η < q/2`. |
| Verificación | `w′ = a·z₁ + z₂ − c·b mod q`. |

Los productos son convolución negacíclica directa (`polynomial_multiplication = schoolbook_negacyclic`), sin NTT. La clase usa `η = 2` por defecto; el benchmark usa `η = 6` para alcanzar 128 bits Core-SVP.

### 4.5 ML-ZKAuth (`proposed_lwe.py`)

Es el protocolo de la tesis. El *docstring* del módulo, la sección «Protocolo propuesto» del README y el capítulo 3 de la tesis describen la misma construcción y deben mantenerse sincronizados. Sus dos fuentes son el manuscrito original y la instrucción de módulo dual de los autores; las 13 lecturas que hubo que fijar están en la tabla del README.

> El nombre del protocolo es ML-ZKAuth (antes, PQLite-Auth v2). La etiqueta de dominio de los hashes conserva el nombre anterior, `lwe-auth/pqlite-auth-v2/dual-modulus/v1`: cambiarla cambiaría todos los hashes e invalidaría los artefactos ya generados.

#### 4.5.1 Dos capas

| Capa | Anillo | Qué vive ahí |
|---|---|---|
| Prueba | `R_q′ = Z_q′[x]/(x²⁵⁶+1)`, q′ = 8 380 417 (el primo de ML-DSA) | Clave de identidad `t = A′·s + e` y la prueba de conocimiento. |
| Transporte | `R_q`, q = 3329 (el de ML-KEM) | Ocultación del token con ML-KEM-768 + AES-256-GCM y acuerdo de clave de sesión. |

#### 4.5.2 Parámetros

Son fijos `d = 256`, `k = 3`, `q = 3329`, `eta = 2` (ruido de la capa de transporte) y `q_proof = 8380417`, junto con descriptores como `kem = ML-KEM-768`, `aead = AES-256-GCM`, `hash = sha3-256` y `ticket_bytes = 32`. Cualquier otro valor se rechaza, incluso uno del mismo valor con otro tipo.

| Ajustable | Por defecto | Rango aceptado y validación |
|---|---|---|
| `k_proof` (k′) | 4 | 3 a 8. |
| `eta_proof` (η′) | 6 | 1 a 8. |
| `kappa` (κ) | 23 | 1 a 256, con espacio de desafíos ≥ 2¹²⁸ (κ = 23 es el menor que lo cumple). |
| `beta` (β) | 138 | Derivado: `η′·κ`. Si se indica, debe coincidir. |
| `gamma1` (γ₁) | 131 072 = 2¹⁷ | De `β + 1` a `q′/8`. |
| `gamma2` (γ₂) | 95 232 = (q′ − 1)/88 | De `β + 1` a `(q′ − 1)/32`, y `2γ₂` debe dividir a `q′ − 1`. |
| `time_window_seconds` | 300 | 1 a 86 400. |

Además, la probabilidad de que un intento del probador se publique debe ser al menos 0.05:

```text
p = ((2(γ₁ − β) − 1) / (2γ₁ − 1))^(k′·d) · ((2(γ₂ − β) − 1) / (2γ₂))^(k′·d)
```

El primer factor es exacto y no depende de la clave. El segundo trata los coeficientes de `w − c·e` como uniformes. Con los valores por defecto, `p = 0.340 · 0.225 = 0.077`: unos 13 intentos por prueba (`acceptance_probability`).

#### 4.5.3 Configuración, registro y reto

```text
Configuración  rho ← 32 bytes aleatorios;  (vpk, vsk) ← ML-KEM-768.KeyGen()
               vsk se registra en el almacén del proceso bajo H(dominio, "verifier-key", vpk)
               system_parameters = {protocol, parameters, rho, vpk}
               A′ = ExpandA_q′(H(dominio, "proof-matrix-seed", rho)) ∈ R_q′^{k′×k′}
               A  = ExpandA_q(rho) ∈ R_q^{3×3}        (flujos SHAKE-128 independientes)
Registro       s, e ← CBD(η′)^{k′};   t = A′·s + e mod q′
               clave pública  {t}: 23 bits por coeficiente (2944 bytes)
               clave privada  {s, e}: η′ + valor con 4 bits por coeficiente (512 bytes cada uno)
                              y public_key_digest = id_C = H(dominio, "public-key", t)
Reto           {ticket: 32 bytes aleatorios, nu: marca de tiempo en ms del reloj del verificador}
```

Las matrices no se almacenan ni se transmiten: cada operación las regenera desde `rho`, y ese costo está incluido en los tiempos medidos. El ticket no depende de la clave pública: la prueba liga la identidad a través de `id_C` en el hash.

#### 4.5.4 Prueba y token (`solve_challenge`)

```text
repetir (como máximo 1000 intentos):
    y  ← uniforme en [−(γ₁ − 1), γ₁ − 1]^(k′·d)
    w  = A′·y mod q′;   w₁ = HighBits(w, 2γ₂)                       (44 valores, 6 bits)
    c̃  = H(dominio, "challenge", H(params), H(A′), id_C, w₁, ticket, nu)
    c  = SampleInBall(c̃): κ coeficientes ±1                          (SHAKE-256)
    z  = y + c·s
    si ‖z‖∞ ≥ γ₁ − β: abortar                                        (oculta s)
    si ‖LowBits(w − c·e, 2γ₂)‖∞ ≥ γ₂ − β: abortar                    (completitud)
token = (tok1, tok2) = seal(vpk, z ‖ c̃ ‖ ticket ‖ nu ‖ id_C,  datos asociados = H(dominio, "token", H(params)))
```

**Por qué una prueba honesta siempre verifica.** El verificador reconstruye `A′·z − c·t = w − c·e`. Como `‖c·e‖∞ ≤ β` y el probador solo publica cuando los bits bajos de `w − c·e` dejan margen, `HighBits(w − c·e) = HighBits(w)`: el verificador calcula el hash sobre la misma entrada. No hay error de completitud; lo único aleatorio es el número de intentos.

Contenido de `tok2` (sin acuerdo de clave):

| Campo | Codificación | Bytes |
|---|---|---|
| `z` | `z + γ₁` con 18 bits por coeficiente (1024 coeficientes) | 2304 |
| `c̃` | semilla del desafío | 32 |
| `ticket` | tal como lo emitió el verificador | 32 |
| `nu` | entero de 64 bits, *big-endian* | 8 |
| `id_C` | `H(t)` | 32 |
| `b_C` (solo con acuerdo de clave) | 768 coeficientes de 12 bits | 1152 |

`tok2` añade el *nonce* (12) y la etiqueta (16): 2436 bytes, o 3588 con `b_C`. Con `tok1` (1088), el token ocupa 3524 bytes, o 4676 con acuerdo de clave. La respuesta del contrato es `{"tok1", "tok2"}` en Base64.

#### 4.5.5 Verificación (`verify_response`)

El orden de las comprobaciones importa, porque determina cuándo se gasta un ticket:

1. **Contexto.** `system_parameters` debe ser de ML-ZKAuth y traer el conjunto efectivo completo, `rho` de 32 bytes y `vpk` de 1184 bytes.
2. **Estado del verificador.** Se busca por `H(vpk)` en el almacén del proceso. Si este proceso no custodia `vsk`, lanza `InvalidProtocolDataError`.
3. **Entradas.** Se decodifican la clave pública `t` (y se calcula `H(t)`) y el reto `(ticket, nu)`.
4. **Descifrado.** `tok1` debe tener 1088 bytes y `tok2` una de las dos longitudes válidas; si no, `InvalidProtocolDataError`. Si la etiqueta no verifica, o el contenido descifrado no decodifica (`z` fuera de rango), devuelve `False`.
5. **Vínculo con el reto y la identidad.** El ticket y `nu` del token deben ser los del reto, y `id_C` debe ser `H(t)` (comparaciones en tiempo constante). Si no coinciden, devuelve `False` **sin gastar el ticket**.
6. **Ventana temporal.** `|ahora − nu| ≤ time_window_seconds`, tanto hacia el pasado como hacia el futuro.
7. **Registro de consumo.** El ticket se consume de forma atómica; si ya estaba gastado, devuelve `False`. Desde este punto, un token inválido también gasta su ticket.
8. **Norma.** `‖z‖∞ < γ₁ − β`.
9. **Ecuación.** Se calcula `w₁′ = HighBits(A′·z − c·t)` y se acepta si `H(…, w₁′, ticket, nu) = c̃`.
10. **Sesión pendiente.** Si acepta, guarda una sesión pendiente (`nu`, `b_C` si vino, y la clave de la respuesta derivada de `K`) que admite una sola respuesta del servidor.

#### 4.5.6 Estado del verificador

El contrato hace públicos los `system_parameters` y el registro crea un objeto nuevo en cada llamada, de modo que `vsk` no puede vivir en ninguno de los dos. Vive en `_KEYSTORE`, un almacén de la memoria del proceso:

- `_VerifierKeystore` guarda hasta 65 536 verificadores y descarta los menos usados (LRU).
- Cada `_VerifierState` tiene la semilla de `vsk`, un *lock*, el registro `spent` (ticket → `nu`) y las sesiones pendientes `authenticated` (ticket → `_PendingSession`).
- Cuando `spent` llega a 8192 entradas, se borran los tickets más antiguos que la ventana, que ya se rechazarían en el paso 6, y las sesiones pendientes vencidas.

Consecuencias: `verify_response` tiene estado (verificar dos veces el mismo token devuelve `False`); si se reinicia el proceso, se pierde `vsk`; y un despliegue con varios procesos necesitaría un almacén compartido con inserción atómica.

El reloj es inyectable, `ProposedLWEAuthProtocol(clock=time.time)`, para probar la ventana temporal sin esperar (`FakeClock` en las pruebas).

#### 4.5.7 Acuerdo de clave de sesión (fuera del contrato)

Son tres métodos que ni el benchmark ni la API ejercitan:

```text
Cliente   solve_challenge_with_key_agreement(...) → (token, sesión del cliente)
              b_C = A·s_C + e_C            (CBD(2) sobre q = 3329, rango 3)
              b_C viaja dentro de tok2, cifrado y autenticado con la prueba
              sesión del cliente = {s: s_C, k: clave de la respuesta}  (secreta, no viaja)
Servidor  generate_session_reply(system_parameters, reto) → ({reply}, K_S)
              solo tras una verificación aceptada cuyo token traía b_C; una vez por ticket
              b_S = Aᵀ·s_S + e_S;   θ_S = b_Cᵀ·s_S + e*_S
              K_S = round₂(θ_S);   v = cross₂(θ_S)
              reply = AES-256-GCM(clave derivada de K, b_S ‖ v)              (1212 bytes)
Cliente   reconcile_session_key(system_parameters, reto, reply, sesión) → K_C
              abre la respuesta (falla si no la cifró quien desencapsuló tok1)
              K_C = rec(b_Sᵀ·s_C, v)                                          (256 bits)
```

La clave de la respuesta es `H(dominio, "session-reply-key", K)` y sus datos asociados son `H(dominio, "session-reply", H(params), ticket)`. Las dos partes obtienen la misma clave si cada coeficiente de `θ_C − θ_S = e_Sᵀ·s_C − e_Cᵀ·s_S − e*_S` está a distancia ≤ 415; el bit de clave tiene el sesgo 1665/3329 que se explica en la sección 3.3. Las cuotas son efímeras y no se reutilizan.

#### 4.5.8 Estado de seguridad (enunciado con precisión)

- La prueba es la plantilla de Dilithium sin compresión de clave pública, con matriz cuadrada, secretos CBD(η′) y `(ticket, nu)` en el lugar del mensaje.
- Es una **NIZK con conocimiento cero estadístico en el modelo de oráculo aleatorio programable**, también frente al verificador designado, que ve exactamente `(z, c̃)`. El simulador elige `c̃`, muestrea `z` uniforme con `‖z‖∞ < γ₁ − β`, repite si `‖LowBits(A′·z − c·t)‖∞ ≥ γ₂ − β` y programa el oráculo.
- Es un **argumento de conocimiento de una relación relajada**: la suplantación descansa en MLWE (que `t` sea pseudoaleatorio) y en SelfTargetMSIS / MSIS sobre `[A′ | I | t]`. Con los valores por defecto, la clave queda en 2^128.2 clásico y 2^116.3 cuántico en Core-SVP, y la solidez en 2^150.7. Core-SVP es una estimación para comparar, no una certificación de categoría NIST.
- Una vez descifrada, `(z, c̃)` es verificable por cualquiera para ese `(ticket, nu)`: la prueba es transferible.
- **No analizado:** el QROM y los canales laterales. El número de intentos se refleja en el tiempo, aunque su distribución no depende de la clave; NumPy no es de tiempo constante; los productos son directos, sin NTT.

Los comentarios `tex:N-M` del código señalan las líneas del manuscrito anterior al 7 de octubre de 2026, no del capítulo actual.

---

## 5. API HTTP

`backend/main.py` crea la aplicación FastAPI (versión 0.2.0) y monta `api/v1/auth.py` bajo `/api/v1`. Los modelos de petición (`schemas.py`) rechazan campos desconocidos.

| Método y ruta | Operación | Cuerpo | Respuesta |
|---|---|---|---|
| `GET /health` | — | — | `{"status": "ok"}` |
| `GET /api/v1/methods` | Protocolos disponibles | — | `{"available_methods": [...]}` |
| `GET /api/v1/protocols` | Catálogo completo con su estado | — | Lista de `ProtocolCatalogEntry` |
| `POST /api/v1/generate_keys` | `resolve_parameters`, `generate_system_parameters` y `generate_keypair` | `protocol_name`, `parameters` | `system_parameters`, `public_key`, `private_key`, `effective_parameters` |
| `POST /api/v1/challenge` | `generate_challenge` | `protocol_name`, `system_parameters`, `public_key` | `{"challenge"}` |
| `POST /api/v1/solve` | `solve_challenge` (**solo para desarrollo**: en un sistema real la clave privada no sale del cliente) | `protocol_name`, `system_parameters`, `private_key`, `challenge` | `{"response"}` |
| `POST /api/v1/verify` | `verify_response` | `protocol_name`, `system_parameters`, `public_key`, `challenge`, `response` | `{"is_valid"}` |

Puntos a tener en cuenta:

- La API no guarda estado de usuarios: el cliente reenvía en cada paso los `system_parameters` que recibió al registrarse.
- `/generate_keys` crea unos `system_parameters` nuevos en cada llamada. Con ML-ZKAuth eso registra un `vsk` nuevo en el proceso de la API; si se reinicia, verificar con esos parámetros devuelve 400.
- Con ML-ZKAuth, `/verify` tiene estado: repetir la misma petición devuelve `is_valid: false`. El acuerdo de clave no está expuesto por HTTP.
- `db/init.sql` crea las tablas `users`, `public_keys` y `auth_challenges`, pero la API actual no las usa.

---

## 6. Framework de benchmarking

### 6.1 Configuración (`config.py`, `configs/default.json`)

`BenchmarkConfig` es un modelo de Pydantic que rechaza claves desconocidas.

| Campo | Por defecto | Corrida oficial | Significado |
|---|---|---|---|
| `experiment_name` | `default-comparison` | `authentication-protocol-comparison` | Nombre del experimento. |
| `target_security_bits` | 128 | 128 | Objetivo de comparación; no prueba nada por sí solo. |
| `warmup_iterations` | 20 | 20 | Autenticaciones de calentamiento, descartadas. |
| `timing_iterations` | 200 | 200 | Repeticiones de cada operación medida (`N`). |
| `authentication_key_sets` | 5 | 5 | Pares de claves entre los que rotan las autenticaciones. |
| `memory_iterations` | 20 | 20 | Repeticiones de la fase de memoria (0 la desactiva). |
| `memory_sample_interval_ms` | 1.0 | 1.0 | Periodo de muestreo de la RSS. |
| `cooldown_seconds_between_protocols` | 1.0 | 1.0 | Pausa entre candidatos. |
| `randomize_protocol_order`, `protocol_order_seed` | `true`, 20260930 | ídem | Orden aleatorio reproducible de los candidatos. |
| `store_raw_samples` | `true` | `true` | Guardar las muestras individuales en la base de datos. |
| `protocol_parameters` | `{}` | ver abajo | Parámetros por candidato, resueltos por el propio protocolo. |
| `network_scenarios` | `[]` | 5 escenarios | Escenarios sintéticos de red (RTT y ancho de banda). |

Parámetros de la corrida oficial (`default.json`), ajustados para que los cinco candidatos de retículos queden entre 2^128.0 y 2^128.6 Core-SVP:

| Candidato | Parámetros |
|---|---|
| `ecdsa` | ninguno |
| `standard_lwe` | `n = m = 1116`, `q = 8380417`, `η = 2`, `ℓ = 128`, `κ = 31`, `γ = 2¹⁷` |
| `binary_lwe` | `n = m = 1196`, resto igual |
| `ring_lwe` | `n = 1024`, `q = 8380417`, `η = 6`, `κ = 16`, `γ = 2¹⁷` |
| `lwr` | `n = m = 1112`, `q = 2²³`, `p = 2²¹`, `η = 2`, `ℓ = 128`, `κ = 31`, `γ = 2¹⁷` |
| `proposed_lwe` | valores por defecto: `k_proof = 4`, `eta_proof = 6`, `κ = 23`, `γ₁ = 2¹⁷`, `γ₂ = 95 232`, ventana de 300 s |

Escenarios de red: `local` (0.2 ms, 1000 Mbit/s), `low-latency` (10 ms, 100 Mbit/s), `medium-latency` (50 ms, 25 Mbit/s), `high-latency` (100 ms, 10 Mbit/s) y `constrained` (250 ms, 1 Mbit/s).

### 6.2 Lanzador y CLI

`scripts/benchmark.sh` prepara una corrida oficial:

1. Crea `backend/benchmark-results/` con permisos para el usuario del contenedor.
2. Si el árbol de trabajo del proyecto tiene cambios, se niega a correr, salvo con `ALLOW_DIRTY_BENCHMARK=1`, que marca la corrida como `git_dirty=true`.
3. Recoge el *commit*, `uname` del anfitrión, las versiones de Docker y Compose y el ID de la imagen. Si la imagen no existe, termina.
4. Salvo con `--no-db`, levanta la base de datos y aplica la migración.
5. Ejecuta `python -m benchmarking.cli` en el contenedor `benchmark` con esos metadatos como variables `BENCHMARK_*` (y `--cpuset-cpus` si se fijó `BENCHMARK_CPUSET`).

`benchmarking/cli.py` acepta `--config`, `--protocol` (repetible; por defecto, todos los disponibles), `--output-dir`, `--notes`, `--no-db` y `--list-protocols`. Ejecuta el experimento, lo persiste en PostgreSQL (salvo con `--no-db`), lo exporta a archivos e imprime un resumen en JSON.

### 6.3 Secuencia de una corrida (`runner.py`)

```text
run_experiment(protocolos)
  ├─ IDs canónicos (un protocolo no puede repetirse)
  ├─ orden: random.Random(semilla).shuffle(...)        (PRNG solo para el orden, no criptográfico)
  ├─ config_sha256 = SHA-256 del JSON canónico de la configuración validada
  ├─ entorno (environment.py) + commit y dirty desde las variables BENCHMARK_*
  └─ por cada protocolo, con una pausa entre ellos:
       run_protocol(spec)
         1. parámetros = resolve_parameters(default.json[protocolo])
         2. verificación de conformidad                        (6.4; aborta si falla)
         3. indicadores de implementación                      (6.10)
         4. calentamiento                                      (6.5)
         5. fase de tiempos: setup, keygen y autenticación     (6.5 y 6.7)
         6. fase de memoria                                    (6.6)
         7. proyección de red                                  (6.9)
         8. estadísticos de todas las mediciones               (6.11)
```

Cada medición es un `Measurement(category, operation, metric_name, value, unit, iteration, metadata)`. Las que tienen `iteration` son muestras y se resumen; las que no la tienen son escalares derivados (rendimiento, proyecciones, indicadores).

### 6.4 Verificación de conformidad (`conformance.py`)

Antes de medir, `run_conformance_checks` ejercita el contrato. Si una comprobación falla, lanza `ProtocolConformanceError` y la corrida se detiene: ese candidato no se puede medir hasta corregirlo.

| Comprobación (clave en los resultados) | Qué se hace |
|---|---|
| `system_setup_json_serializable` | Serializa los `system_parameters` en JSON canónico. |
| `json_serializable` | Serializa claves, retos y respuesta. |
| `fresh_challenges` | Genera dos retos seguidos y exige que sean distintos. |
| `valid_round_trip` | Una respuesta honesta al reto A debe verificar. |
| `rejects_replayed_response_on_new_challenge` | La misma respuesta no debe verificar con el reto B. |
| `rejects_tampered_response` | Modifica mínimamente el primer campo de la respuesta y exige rechazo o `InvalidProtocolDataError`. |
| `rejects_response_under_other_public_key` | La respuesta no debe verificar con la clave pública de otro usuario. |
| `does_not_mutate_inputs` | Los `system_parameters` y las claves no cambiaron (comparación con copias profundas). |

Sobre `rejects_tampered_response`: como todos los campos son cadenas Base64, la modificación (añadir un carácter) produce una cadena que no es Base64 válida, así que en la práctica comprueba que se rechaza una respuesta mal formada. Las pruebas específicas de cada protocolo cubren alteraciones de un bit con formato válido (sección 8).

En la corrida oficial, los seis candidatos superaron las ocho comprobaciones.

### 6.5 Medición de tiempo

**Relojes:** `time.perf_counter_ns()` para el tiempo de pared y `time.process_time_ns()` para el tiempo de CPU del proceso, en milisegundos. El tiempo de CPU suma todos los hilos del proceso: puede superar al de pared si una biblioteca usa varios hilos, como BLAS en el registro de los candidatos de matriz.

1. **Calentamiento:** una configuración y `warmup_iterations` ciclos de registro, reto, respuesta y verificación; todos deben verificar.
2. **Configuración (`setup`):** `N` llamadas a `generate_system_parameters`, cada una medida. La primera se conserva como la configuración representativa para el resto de la corrida. Cada iteración registra también los tamaños de la sección 6.7.
3. **Registro (`keygen`):** `N` llamadas a `generate_keypair` sobre la configuración representativa, más sus tamaños.
4. **Autenticación:** antes del bucle se generan `authentication_key_sets` pares de claves, fuera del temporizador. En la iteración `i` se usa el par `i mod 5` y:
   - se miden por separado `challenge`, `response` y `verify` sobre el mismo reto, que debe verificar;
   - se mide una **autenticación completa independiente** (`authentication`), con un reto nuevo. Por eso el total no coincide con la suma de las etapas: son autenticaciones distintas (en los candidatos de retículos, con distinto número de intentos del probador);
   - con el reto y la respuesta de las etapas se registran la comunicación (6.7) y la serialización (6.8).
5. **Rendimiento secuencial (`throughput/authentication/sequential_rate`):** `1000 · N / Σ tiempo de pared de las autenticaciones completas`, en autenticaciones por segundo. No se promedian valores de `1/latencia`, y no representa la capacidad concurrente de un servidor.

### 6.6 Medición de memoria (`memory.py`)

La memoria se mide en una fase aparte, porque la instrumentación altera los tiempos. Para cada operación (`setup`, `keygen`, `challenge`, `response`, `verify`, `authentication`) se hacen `memory_iterations` repeticiones de `observe_memory(operación)`:

- `tracemalloc` se activa solo durante la operación; `peak_python_alloc` es el pico de asignaciones de Python.
- Un hilo muestrea la RSS del proceso con `psutil` cada `memory_sample_interval_ms`. `peak_rss_delta` es el máximo observado menos la RSS inicial (con una lectura final), y `mean_rss_delta` la media de los incrementos sobre la RSS inicial en todas las muestras, contando como cero los negativos.
- `verify` usa en cada repetición un reto y una respuesta nuevos, construidos fuera de la región medida: un verificador con estado (el registro de tickets de ML-ZKAuth) rechazaría una repetición, y se mediría el rechazo de un *replay*. Si una verificación medida se rechaza, la corrida falla. `response` repite el mismo reto, porque el probador no tiene estado.

Límites: `tracemalloc` no ve toda la memoria nativa de OpenSSL o de NumPy, y el muestreo de RSS puede perder picos muy breves y no capta asignaciones que reutilizan memoria ya reservada. En la corrida oficial la RSS no aumentó durante la autenticación en ningún candidato; por eso la tesis compara el pico de `tracemalloc`.

### 6.7 Tamaños, almacenamiento y comunicación (`serialization.py`)

Todos los tamaños son los del **JSON canónico** de lo que devuelve el protocolo: claves ordenadas, separadores compactos y UTF-8 (`canonical_json_bytes`). Con Base64, superan en cerca de un tercio a los tamaños binarios. Un mensaje se envuelve en un sobre canónico, `{"type", "protocol", "payload"}` (`wire_message_bytes`), sin cabeceras HTTP, TLS ni TCP/IP.

| Categoría | Operación | Métricas |
|---|---|---|
| `artifact_size` | `setup` | `system_parameters` |
| `artifact_size` | `enrollment` | `public_key`, `private_key` |
| `artifact_size` | `authentication` | `challenge`, `response` |
| `storage` | `shared_deployment` | `system_parameters` (una vez por despliegue) |
| `storage` | `per_user` | `server_persistent` (clave pública), `client_persistent` (clave privada), `combined_persistent` |
| `communication` | `setup` | `system_parameters_distribution` (sobre; no se suma a cada autenticación) |
| `communication` | `enrollment` | `public_key_registration` (sobre) |
| `communication` | `authentication` | `challenge_message`, `response_message`, `total_application_payload` (sobres), `message_count = 2`, `round_trips = 1` |

El conteo de mensajes y de viajes es constante: el benchmark mide los dos mensajes del contrato (reto y respuesta). Un inicio de sesión real añade la solicitud inicial y el aviso del resultado, comunes a los seis candidatos, y el acuerdo de clave de ML-ZKAuth no se mide.

### 6.8 Serialización

En cada iteración de autenticación se mide, en la categoría `serialization`, el tiempo de serializar a JSON canónico y de deserializar (`json.loads`) el reto y la respuesta: `serialize_challenge`, `deserialize_challenge`, `serialize_response` y `deserialize_response`. Ese tiempo no se mezcla con el de las operaciones criptográficas.

### 6.9 Proyección de red (`network.py`)

Para cada escenario se calcula, una sola vez por candidato:

```text
transporte  = round_trips · RTT + 8 · B / (ancho de banda en bit/s)      con round_trips = 1
e2e         = media(autenticación completa) + media(serialización por autenticación) + transporte
```

`B` es la media de `total_application_payload`, redondeada, y la serialización por autenticación es la suma de los tiempos de las cuatro operaciones de serialización dividida entre `N`. Se guardan como `network_projection/authentication/transport_time` y `projected_e2e_time`, con el escenario en los metadatos. No tienen iteración, así que no aparecen en `summaries.csv`: están en `measurements.csv` y en `experiment.json`.

Es un modelo determinista para comparar, no una emulación: no incluye el establecimiento de la conexión, TLS, las cabeceras, la pérdida de paquetes, las retransmisiones ni la congestión. Cuenta un solo viaje de ida y vuelta (el par reto–respuesta); un inicio de sesión completo suma otro.

### 6.10 Indicadores de implementación (`code_metrics.py`)

Por candidato se registran el número de parámetros efectivos, el número de dependencias declaradas, las líneas de código no vacías y no comentadas, el tamaño del código y el SHA-256 de las fuentes. Se cuentan el archivo de la clase registrada y los de sus clases base dentro de `crypto_core` (excepto `interface.py`), de modo que cada candidato de retículos incluye `lattice_zk.py` y los de matriz también `matrix_lwe_zk.py`. Los módulos solo importados (`crypto_core/lwe/`, `token_hiding.py`) no se cuentan.

Son indicadores, no una puntuación. Desde el 22 de octubre de 2026 la tesis no usa la complejidad de implementación como criterio de comparación, aunque el benchmark los sigue registrando.

### 6.11 Estadísticos (`statistics.py`)

`summarize_measurements` agrupa las mediciones con iteración por `(categoría, operación, métrica, unidad, metadatos)` y calcula:

- número de muestras, media (`statistics.fmean`), mediana y desviación estándar muestral (con `n − 1`);
- mínimo y máximo;
- percentiles 95 y 99 por interpolación lineal entre estadísticos de orden, como el método por defecto de NumPy.

### 6.12 Entorno y reproducibilidad (`environment.py`)

Cada experimento guarda:

- Python (versión, implementación, ejecutable) y SageMath;
- plataforma y sistema del contenedor;
- CPU: modelo, núcleos físicos y lógicos, frecuencia;
- carga del sistema, afinidad de CPU y `nice` del proceso;
- memoria visible y límite del *cgroup*;
- versiones de los paquetes relevantes y el inventario completo de paquetes de Python;
- lo que inyecta el lanzador: ID de la imagen, `uname` del anfitrión, versiones de Docker y Compose y el CPU set solicitado.

Además se guardan el *commit*, el indicador de cambios sin *commit*, la configuración completa con su `config_sha256`, las marcas de tiempo UTC de inicio y fin y el orden real de los candidatos.

`config_sha256` es el SHA-256 del JSON canónico de la configuración ya validada, incluidos los valores por defecto, no de los bytes del archivo.

La aleatoriedad criptográfica nunca se fija con una semilla: la reproducibilidad se refiere al código, los parámetros, el entorno y el procedimiento.

### 6.13 Exportación y persistencia (`export.py`, `persistence.py`)

`export_experiment` crea `benchmark-results/<experiment_id>/`:

- `experiment.json`: el manifiesto completo, con configuración, entorno, metadatos, comprobaciones de conformidad, mediciones y resúmenes.
- `measurements.csv`: una fila por medición (`run_id, protocol_name, category, operation, metric_name, iteration, value, unit, metadata_json`).
- `summaries.csv`: una fila por resumen (`…, sample_count, mean, median, stddev, minimum, p95, p99, maximum, metadata_json`).

`BenchmarkRepository` escribe en PostgreSQL (`DATABASE_URL`). Crea el experimento en estado `RUNNING`, luego cada corrida de protocolo con sus mediciones (solo si `store_raw_samples`) y resúmenes, y marca `SUCCESS` o `FAILED`. Las tablas (`db/migrations/001_benchmarking.sql`) son:

| Tabla | Contenido |
|---|---|
| `benchmark_experiments` | Configuración, `config_sha256`, entorno, *commit*, orden y estado. |
| `benchmark_protocol_runs` | Una fila por candidato y experimento: parámetros, conformidad y estado. |
| `benchmark_measurements` | Muestras individuales. |
| `benchmark_summaries` | Estadísticos agregados. |
| `benchmark_protocol_assessments` | Criterios cualitativos con evidencia (sección 6.14). |
| `benchmark_security_assessments` | Estimaciones de seguridad con herramienta, versión, supuestos y evidencia. |

Las claves privadas nunca se guardan; solo su tamaño.

### 6.14 Evaluaciones cualitativas y de seguridad

Las cifras de seguridad y los criterios cualitativos no los inventa el benchmark. Se registran aparte y siempre con evidencia:

- **`security.py` y `security_cli.py`:** un `SecurityAssessment` exige al menos una cifra, clásica o cuántica. Para guardarlo exige además un `protocol_id` real y evidencia no vacía, y comprueba que el `--run-id` corresponda a ese protocolo. Plantilla: `configs/security.template.json`. `hardness_cli` produce archivos en este formato (sección 7).
- **`assessment.py` y `assessment_cli.py`:** un `ProtocolAssessment` agrupa criterios `{value, evidence}` en cinco dimensiones (`implementation`, `operational`, `trust_architecture`, `maturity` y `security`). Plantilla: `configs/assessment.template.json`, con todos los valores en `null` a propósito.

Ambas CLI admiten `--validate-only` para validar sin escribir en la base de datos.

---

## 7. Estimación de la dureza

El benchmark nunca deriva bits de seguridad. `benchmarking/hardness.py` traduce los parámetros efectivos de cada candidato a los problemas de retículos en que descansa su seguridad y los evalúa con el [*lattice-estimator*](https://github.com/malb/lattice-estimator) (*commit* `53da598`). El procedimiento completo y su validación están en [`estimacion-de-dureza.md`](estimacion-de-dureza.md).

### 7.1 Instancias por candidato (`hardness.instances`)

| Candidato | Clave (LWE) | Solidez (SIS en norma ∞) |
|---|---|---|
| `standard_lwe` | `n = m = 1116`, `q`, secreto y error CBD(η) | `[A \| I \| B]`: `m × (n + m + ℓ)`, cota `γ − κ·η` |
| `binary_lwe` | `n = m = 1196`, secreto uniforme en `{0, 1}`, error CBD(η) | ídem, cota `max(γ − κ, γ − κ·η)` |
| `lwr` | `n = m = 1112`, `q = 2²³`, secreto CBD(η), error uniforme en `[1 − q/2p, q/2p] = {−1, …, 2}` | ídem, cota `max(γ − κ·η, γ − κ·q/2p)` |
| `ring_lwe` | LWE de dimensión `n = 1024`, CBD(η) | `[a \| 1 \| b]` como SIS de `n × 3n`, cota `γ − κ·η` |
| `proposed_lwe` | MLWE como LWE de dimensión `k′·d = 1024`, `q′`, CBD(η′) | SelfTargetMSIS sobre `[A′ \| I \| t]`: `1024 × (2k′ + 1)·d`, cota `max(γ₁ − β, γ₂ + 1)` |
| `proposed_lwe` (transporte) | LWE de dimensión 768, `q = 3329`, CBD(2) | — (se informa aparte) |

La cota de solidez es la de la componente de la respuesta que el verificador deja más grande: la mayor de las cotas de `z₁` y `z₂`.

Decisiones de modelado, explícitas en la descripción de cada instancia: MLWE y Ring-LWE se estiman como LWE de la misma dimensión, porque no se conoce un ataque que aproveche la estructura a estos tamaños; LWR se estima como LWE con error uniforme sobre el intervalo de redondeo, la heurística de Saber; la solidez es la instancia SIS que produciría un falsificador.

### 7.2 Cálculo (`hardness.estimate`)

- **LWE:** ataque primal uSVP (forma GSA) y dual híbrido.
- **SIS:** `SIS.lattice` en norma infinito.
- **Coste:** modelo Core-SVP de Alkim, Ducas, Pöppelmann y Schwabe (`ADPS16`): 2^(0.292·b) clásico y 2^(0.265·b) cuántico, con `b` el bloque de BKZ.
- **Resultado de cada instancia:** el ataque clásico más barato. La cifra cuántica es el mínimo entre ataques.

ECDSA no se estima: `hardness.LITERATURE` cita 128 bits clásicos (NIST SP 800-57) y 0 cuánticos (el algoritmo de Shor lo rompe en tiempo polinomial).

### 7.3 Uso (`hardness_cli.py`)

```bash
# desde lwe-auth-project/, con el estimador clonado en ../lattice-estimator (commit 53da598)
MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps -T \
  -v "$(cd ../lattice-estimator && pwd -W)":/estimator \
  benchmark sage -python -m benchmarking.hardness_cli --output-dir benchmark-results/hardness
```

Por cada candidato imprime cada ataque con su bloque y su coste, y escribe `<protocolo>.security.json` (listo para `security_cli`) y `<protocolo>.raw.json`. La cifra de la autenticación es el mínimo entre la clave y la solidez; la capa de transporte de ML-ZKAuth se informa aparte. Los parámetros se resuelven con el propio protocolo, así que un cambio en `default.json` se refleja solo. `pwd -W` es para Docker Desktop en Windows; en Linux basta `pwd`.

Resultado con `default.json` (de `estimacion-de-dureza.md`):

| Candidato | Clave: ataque, bloque | Clave: clásico / cuántico | Solidez: bloque, clásico |
|---|---|---|---|
| `proposed_lwe` | primal, 439 | 2^128.2 / 2^116.3 | 516, 2^150.7 |
| `standard_lwe` | dual híbrido, 438 | 2^128.0 / 2^116.9 | 577, 2^168.5 |
| `ring_lwe` | primal, 439 | 2^128.2 / 2^116.3 | 516, 2^150.7 |
| `binary_lwe` | dual híbrido, 440 | 2^128.5 / 2^117.9 | 631, 2^184.3 |
| `lwr` | dual híbrido, 440 | 2^128.6 / 2^117.4 | 575, 2^167.9 |

La capa de transporte de ML-ZKAuth queda en 2^174.3.

### 7.4 Búsqueda de la capa de prueba de ML-ZKAuth (`proof_layer_search.py`)

Reproduce la tabla `tab:pqlite_busqueda` del capítulo 3 de la tesis. Para cada par `(k′, η′)` de la rejilla (3:2, 4:2, 4:4, 4:5, 4:6, 4:7, 4:8 y 5:2) calcula la dureza de la clave, con la misma instancia y las mismas llamadas que `hardness`, y la probabilidad de aceptación por intento con la misma función del protocolo, junto con los intentos medios. Evalúa también pares que `resolve_parameters` rechaza, como η′ = 8 con aceptación menor que 0.05, para mostrar por qué se descartaron.

```bash
make proof-layer-search                               # clona el estimador si falta
./scripts/proof-layer-search.sh --without-hardness    # solo aceptación e intentos
./scripts/proof-layer-search.sh --grid 4:6,5:2 --output filas.json
```

---

## 8. Pruebas

### 8.1 Cómo ejecutarlas

Todas usan `unittest` y corren dentro del contenedor, desde `/app` (`backend/`):

```bash
make test                                             # toda la batería
docker compose run --rm --no-deps -T benchmark sage -python -m unittest tests.test_proposed_lwe -v
docker compose run --rm --no-deps -T benchmark \
  sage -python -m unittest tests.test_proposed_lwe.RejectionSamplingTests -v
# con el lattice-estimator montado se ejecutan también las 3 pruebas que lo necesitan
MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps -T \
  -v "$(cd ../lattice-estimator && pwd -W)":/estimator \
  benchmark sage -python -m unittest tests.test_hardness tests.test_proof_layer_search -v
```

`unittest discover` solo recoge archivos `test*.py`; `lattice_zk_cases.py` es un *mixin* que los módulos de cada candidato incorporan.

### 8.2 Inventario

Hay 278 métodos de prueba en 18 módulos. Tres se saltan si el *lattice-estimator* no está montado (`EstimatorValidationTests` y `HardnessColumnTests`).

| Módulo | Pruebas | Qué cubre |
|---|---|---|
| `test_proposed_lwe.py` | 109 | ML-ZKAuth completo (sección 8.4). |
| `test_lwe_zk.py` | 59 | `standard_lwe` y `binary_lwe` (batería común + relación de la clave, espacio de desafíos y distribución del secreto) y los muestreadores y códecs de la plantilla. |
| `test_ring_lwe.py` | 28 | `ring_lwe` (batería común + relación) y la multiplicación negacíclica contra una referencia. |
| `test_lwr.py` | 27 | `lwr` (batería común + `B = ⌊p/q·A·S⌉` y relación elevada con `‖E‖∞ ≤ q/2p`) y el redondeo. |
| `test_hardness.py` | 10 | Que cada candidato tenga instancias de clave y de solidez, parámetros equiparados, intervalo de error de LWR igual al redondeo del código, ECDSA citado, CLI; con el estimador, que se reproduzcan Kyber512 (`b = 406`) y Dilithium2 (`b = 423`) y que cada instancia llegue a 2^128 sin que ninguna clave pase de 2^129. |
| `test_registry.py` | 8 | Exactamente seis candidatos, todos disponibles, alias, fallo cerrado de una entrada sin implementación, ID desconocido. |
| `test_api_contract.py` | 6 | Catálogo; ida y vuelta HTTP de ECDSA, de un candidato de retículos y de ML-ZKAuth (con rechazo del *replay*); errores 400. |
| `test_ecdsa.py` | 6 | Ida y vuelta, reto modificado, clave mal formada, parámetros explícitos y fijos, sin *setup*. |
| `test_proof_layer_search.py` | 5 | Rejilla, aceptación e intentos iguales a la tabla de la tesis, CLI; con el estimador, la dureza de la tabla. |
| `test_benchmark_config.py` | 4 | Nombres de escenarios únicos, claves desconocidas rechazadas, `default.json` válido. |
| `test_benchmark_runner.py` | 4 | Una corrida pequeña produce todas las familias de métricas; la fase de memoria mide verificaciones aceptadas con un verificador con estado; huella de la configuración y marcas de tiempo. |
| `test_protocol_conformance.py` | 2 | Los seis candidatos superan la verificación de conformidad con sus valores por defecto. |
| `test_benchmark_statistics.py`, `test_benchmark_serialization.py`, `test_benchmark_security.py`, `test_code_metrics.py` | 2 cada uno | Estadísticos, JSON canónico, validación de assessments de seguridad, archivos que cuentan los indicadores. |
| `test_benchmark_network.py`, `test_benchmark_assessment.py` | 1 cada uno | Fórmula de la proyección; registros de un assessment cualitativo. |

### 8.3 Batería común de los candidatos de retículos (`lattice_zk_cases.py`)

`LatticeZKProtocolCases` tiene 24 casos que se ejecutan para `standard_lwe`, `binary_lwe`, `lwr` y `ring_lwe`. Usa parámetros pequeños pero válidos (`n = m = 128`) para que la batería sea rápida; un caso repite el flujo con los parámetros por defecto.

| Grupo | Casos |
|---|---|
| Completitud (2) | 20 autenticaciones honestas verifican; ida y vuelta con los parámetros por defecto. |
| Solidez y vínculo (7) | El reto es un *nonce* fresco; la prueba no verifica con otro *nonce* ni con otra clave pública; la clave privada de otro usuario no convence; **cambiar un bit de cualquier campo de la respuesta** la invalida; un coeficiente por encima de la cota se rechaza; una respuesta aleatoria con el `c̃` correcto se rechaza. |
| Conocimiento cero, comprobaciones estadísticas (3) | Con 30 pruebas (≥ 3840 coeficientes), `z` tiene media ≈ 0 y desviación ≈ cota/√3, la de la uniforme en la caja; dos pruebas para el mismo *nonce* son distintas y ambas verifican; la respuesta no contiene material del testigo. |
| Entradas mal formadas (3) | Clave privada con Base64 inválido, sin un campo o con un resumen de otro tamaño; testigo fuera de su distribución; clave pública, reto o respuesta mal formados. |
| Parámetros (2) | Los parámetros efectivos son explícitos; se rechazan claves desconocidas, tipos incorrectos, κ que no da 2¹²⁸ desafíos, γ demasiado pequeño o grande, `q > 2²⁴` y cambios a valores fijos. |
| Configuración, serialización y mutación (7) | `system_parameters` con el material compartido y los parámetros; material nuevo en cada *setup*; registro con parámetros distintos del *setup*; parámetros de otro protocolo o no canónicos rechazados; todo artefacto serializable; ninguna operación modifica sus entradas. |

### 8.4 Pruebas de ML-ZKAuth (`test_proposed_lwe.py`)

`_Deployment` crea un despliegue y un cliente con un reloj falso (`FakeClock`). Los ayudantes `_attempt` y `_attempt_where` reproducen un intento del probador paso a paso para fabricar casos límite.

| Clase | Pruebas | Qué demuestra |
|---|---|---|
| `ParameterTests` | 8 | Valores del manuscrito y módulo de prueba; valores fijos inmutables; valores por defecto documentados; `β` derivado; rangos y validaciones; aceptación prevista por intento. |
| `PrimitiveTests` | 11 | CBD y máscara en su rango; expansión de matrices determinista, en rango y con respuestas conocidas fijadas; empaquetado de bits; aritmética de módulos contra una referencia ingenua; sin desbordamiento de `int64`; identidad del acuerdo de clave con `Aᵀ`; y, con SageMath, la aritmética coincide con el anillo cociente para ambos módulos. |
| `DecompositionTests` | 6 | 44 valores altos; descomposición exacta para todo residuo; plegado del intervalo superior; los bits altos sobreviven a un desplazamiento de β cuando los bajos dejan margen y pueden cambiar cuando no. |
| `ReconciliationTests` | 7 | Fórmulas del manuscrito; acuerdo exacto para toda entrada y todo error hasta 415; no garantizado en 416; claves de 256 bits idénticas con ruido aleatorio bajo la cota; pista casi independiente del bit. |
| `AuthenticationFlowTests` | 37 | El flujo completo. Incluye: 100 de 100 autenticaciones honestas aceptadas; aceptación independiente de la clave y del despliegue; relación de la clave; tickets frescos; prueba ligada al ticket, a la marca de tiempo y a la clave; `id_C` dentro del token; *replay* rechazado; ticket gastado incluso con prueba inválida; ventana temporal (dentro, vencida, en el futuro); falsificaciones rechazadas; token opaco de tamaño esperado; solo el verificador designado lo abre; cualquier modificación se rechaza; tamaños de claves; entradas mal formadas; y la verificación de conformidad común superada sin modificarla. |
| `RejectionSamplingTests` | 5 | Las dos ramas de aborto ocurren con las tasas previstas (300 pruebas); el verificador rechaza un hash válido con `z` demasiado grande y un `z` exactamente en la cota; la condición de bits bajos es la que hace que toda prueba publicada verifique; el probador se rinde tras el límite de intentos. |
| `NarrowMaskTests`, `NonPowerOfTwoMaskTests` | 2 + 2 | Con γ₁ = 2¹⁴ casi todos los intentos abortan y la aceptación sigue siendo total; con γ₁ = 100 000 un token auténtico con `z` no decodificable se rechaza. |
| `ProofRankThreeTests` | 4 | El rango 3 del manuscrito sigue funcionando, con tamaños menores; claves y pruebas de otro rango se rechazan; supera la conformidad. |
| `SessionKeyAgreementTests` | 10 | Las dos partes obtienen la misma clave en muchas sesiones; `b_C` viaja cifrado; la respuesta exige una autenticación aceptada y se emite una sola vez; un token sin cuota no recibe respuesta; otro secreto no deriva la clave; una respuesta que no selló el verificador se rechaza; el ruido queda muy por debajo de la cota; entradas mal formadas. |
| `ManuscriptDeviationTests` | 8 | La evidencia de cada lectura que se apartó del manuscrito: el desafío matricial rompe la cancelación; el desafío escalar corto la restablece; un desafío uniforme anula las cotas; el compromiso dentro del token entregaría la clave; la máscara CBD del manuscrito no oculta el secreto; la fórmula de reconciliación impresa no tolera error; la tabla de cuadrantes contradice la fórmula; la clave encapsulada sustituye a la elegida por el cliente. |
| `DualModulusRationaleTests` | 3 | Por qué la prueba necesita su propio módulo: sobre q = 3329 ningún paso de redondeo da una aceptación usable (< 10⁻¹⁵) ni cabe una máscara que oculte el secreto; q′ tiene los pasos de ML-DSA. |
| `ZeroKnowledgeEvidenceTests` | 6 | El token lleva `z` y `c̃`, nunca el compromiso; **el simulador**, sin `s` ni `e`, produce una transcripción que el verificador acepta cuando el oráculo está programado (y rechaza con el hash real: simular no es falsificar); simulador y probador pasan la condición de bits bajos con la misma tasa; las respuestas publicadas son uniformes en su caja (soporte, momentos y χ² sobre más de 100 000 coeficientes); el estimador por mínimos cuadrados que rompía la construcción anterior no aprende nada con 60 tokens; el valor que reconstruye el verificador no es el término de error. |

### 8.5 Alcance de las pruebas

- Las comprobaciones estadísticas (uniformidad, tasas de aborto, simulador) son **evidencia, no demostraciones**. Usan aleatoriedad real con tolerancias amplias (más de 4 errores estándar), de modo que un fallo espurio es posible pero muy improbable.
- Las pruebas no cubren la persistencia en PostgreSQL, los scripts de shell, el tiempo constante, el QROM ni redes reales.
- La generación aleatoria de los propios casos de prueba puede usar el generador de NumPy (por ejemplo, la respuesta aleatoria de la batería común); los protocolos nunca lo usan.

---

## 9. De los resultados a las cifras de la tesis

### 9.1 Corrida oficial

| Dato | Valor |
|---|---|
| ID del experimento | `42c5501d-56c8-48d1-b630-695b6d4eb70f` |
| Fecha | 20 de octubre de 2026, de 13:50 a 13:52 UTC |
| *Commit* | `05a59f7b7e7e05fdb5d6140417e338b23e6b1b3d`, `git_dirty = false` |
| Configuración | `benchmarking/configs/default.json`, `config_sha256 = 004fdaa1bf1a817e8819e5cf9ffeb0b83bcd28baad0690f447ca1481eef45daf` |
| Imagen | `lwe-auth-project-api:local` (`e59db430fb1a`) |
| Persistencia | `--no-db`: la corrida está en los archivos exportados, no en PostgreSQL. |
| Orden | ECDSA, LWR, Binary-LWE, LWE, ML-ZKAuth, Ring-LWE (semilla 20260930) |
| Conformidad | Las ocho comprobaciones superadas por los seis candidatos. |
| Entorno | AMD Ryzen 7 9700X con Windows 11 y WSL2; contenedor con 16 CPU lógicas y 30.2 GiB; SageMath 10.10, Python 3.12.3, `cryptography` 50.0.2 (OpenSSL 4.0.3), NumPy 2.4.4. |

Los archivos están en `backend/benchmark-results/42c5501d-…/`, que **no se versiona en Git**: conviene archivarlos junto a la entrega de la tesis.

### 9.2 Correspondencia entre tablas y datos

Todas las cifras de tiempo son el tiempo de pared (`wall_time`) en milisegundos. Los KB de memoria son bytes entre 1024 y los demás tamaños se dan en bytes.

| Tabla o figura de la tesis (etiqueta) | Fuente | Filtro y estadístico |
|---|---|---|
| Tiempo de generación de claves (`tab:keygen-time`) | `summaries.csv` | `timing / keygen / wall_time`: media, mediana, desviación, percentiles 95 y 99 y máximo. |
| Tiempo por etapa (`tab:authentication-time`) y figuras `fig:auth-time-comparison`, `fig:auth-stage-comparison` | `summaries.csv` | `timing / {setup, keygen, challenge, response, verify, authentication} / wall_time`: media. |
| Rendimiento (columna de `tab:authentication-time`) | `measurements.csv` | `throughput / authentication / sequential_rate` (sin iteración). |
| Distribución de los tiempos | `summaries.csv` | `timing / authentication / wall_time`: mediana, p95, p99, máximo. |
| Memoria (`tab:memory-results`) | `summaries.csv` | `memory / <operación> / peak_python_alloc`: media ÷ 1024. Los incrementos de RSS (`mean_rss_delta`, `peak_rss_delta`) se comentan en el texto. |
| Tamaños (`tab:key-sizes`) | `summaries.csv` | `artifact_size / setup / system_parameters` y `artifact_size / enrollment / {public_key, private_key}`: media. «Total registro» = `storage / per_user / combined_persistent`. |
| Comunicación (`tab:communication`) | `summaries.csv` | `communication / authentication / {challenge_message, response_message, total_application_payload}`. *Metadata* = total − `artifact_size` del reto − `artifact_size` de la respuesta. |
| Proyección de red (`tab:network-projection`) | `measurements.csv` | `network_projection / authentication / projected_e2e_time`, un valor por escenario. El segundo viaje de ida y vuelta de un inicio de sesión completo se suma en el texto (sección de requisitos operacionales). |
| Escalabilidad del almacenamiento (`tab:storage-scalability`) | `summaries.csv` | Clave pública (`server_persistent`) × número de usuarios. |
| Resumen global (`tab:global-summary`) | Las anteriores | Combinación de las filas anteriores y de la seguridad estimada. |
| Seguridad estimada (`tab:security-levels`, `tab:pqlite_dureza`) | `hardness_cli` | No sale de la corrida (sección 7). |
| Búsqueda de `(k′, η′)` (`tab:pqlite_busqueda`) | `proof_layer_search` | Sección 7.4. |
| Tamaños analíticos de ML-ZKAuth (sección «Tamaños y costos analíticos») | Código | Constantes de `proposed_lwe.py` y `token_hiding.py` (sección 4.5.4). |

Las cifras se extrajeron con un script auxiliar que no forma parte del repositorio; los filtros de la tabla bastan para repetir la extracción sobre `summaries.csv` y `measurements.csv`.

---

## 10. Mantenimiento y extensión

- **Agregar un candidato:** sigue los pasos de la sección «Cómo implementar un candidato pendiente» del README. Va en `crypto_core/protocols/`, se registra reemplazando solo su `implementation_factory`, con pruebas propias y superando la conformidad. Si es de retículos, conviene montarlo sobre `lattice_zk.py` para que las diferencias se atribuyan al supuesto. Los seis ID son fijos: un séptimo candidato cambiaría la metodología.
- **Cambiar parámetros:** edita `default.json`, vuelve a ejecutar `hardness_cli` y mantén a los candidatos equiparados; con el estimador montado, `test_hardness` exige que cada clave quede entre 2^128 y 2^129.
- **Cambiar ML-ZKAuth:** no se cambia la criptografía sin que los autores lo pidan. Toda desviación nueva se registra en el *docstring*, en el README y en el capítulo 3 de la tesis, con su evidencia en `ManuscriptDeviationTests`.
- **Corrida oficial:** con el árbol de trabajo limpio y la imagen construida, `./scripts/benchmark.sh` (o `--no-db` si no se usará PostgreSQL). Si la imagen que indica `.env` no tiene las dependencias, exporta `API_IMAGE_NAME=lwe-auth-project-api:local`. Archiva después la carpeta de resultados.

---

## 11. Limitaciones y observaciones conocidas

**Del prototipo:**

- La aritmética de retículos está en Python con NumPy: no es de tiempo constante y multiplica polinomios con la convolución directa `O(n²)`, sin NTT. ECDSA, ML-KEM y AES usan código compilado de OpenSSL, así que las diferencias de tiempo frente a ECDSA mezclan algoritmo e implementación.
- La expansión de matrices desde semilla tiene un formato de bytes propio; no es interoperable con Kyber ni con Dilithium.
- El estado del verificador de ML-ZKAuth vive en la memoria de un proceso (sección 4.5.6).
- La API no persiste usuarios ni retos: las tablas `users`, `public_keys` y `auth_challenges` existen, pero no se usan. `/solve` existe solo para desarrollo.

**Del benchmark:**

- La comunicación y la proyección de red cuentan los dos mensajes del contrato, en un viaje de ida y vuelta. Un inicio de sesión real tiene cuatro mensajes y dos viajes, y el acuerdo de clave de ML-ZKAuth (+1152 bytes en el token y 1212 en la respuesta) no se mide.
- En los candidatos de matriz, los tiempos y la memoria incluyen decodificar la matriz pública desde JSON en cada operación; en ML-ZKAuth, regenerar `A′` con SHAKE-128.
- La comprobación `rejects_tampered_response` de la verificación de conformidad comprueba, en la práctica, el rechazo de una respuesta mal formada (sección 6.4).
- `assessment_cli` guarda un assessment cualitativo sin llamar a `assert_ready_for_persistence`, a diferencia de `security_cli`: un archivo con criterios en `null` o sin evidencia se puede guardar.
- Los resultados (`backend/benchmark-results/`) no están en Git.

**Restos históricos en el código:**

- La etiqueta de dominio `pqlite-auth-v2` se conserva a propósito (sección 4.5).
- Los comentarios `tex:N-M` apuntan al manuscrito anterior.
- El *docstring* de `lattice_zk.py` menciona un «protocolo anterior basado en cifrado».
- `lwe/keygen.py` y varias funciones de `sampling.py` y `codec.py` no las usa ningún candidato.

---

## Anexo A. Notación

| Símbolo | Código | Significado |
|---|---|---|
| `n`, `m` | `n`, `m` | Dimensión del secreto y número de muestras (filas de `A`). |
| `ℓ` | `ell` | Columnas secretas de los candidatos de matriz. |
| `q` | `q` | Módulo; en ML-ZKAuth, el de la capa de transporte (3329). |
| `q′` | `q_proof` | Módulo de la capa de prueba de ML-ZKAuth (8 380 417). |
| `p` | `p` | Módulo de redondeo de LWR. |
| `d` | `d` | Grado del anillo de ML-ZKAuth (256). |
| `k`, `k′` | `k`, `k_proof` | Rango de la capa de transporte (3) y de la capa de prueba (4). |
| `η`, `η′` | `eta`, `eta_proof` | Parámetro de la binomial centrada CBD. |
| `κ` | `kappa` | Peso del desafío (coeficientes no nulos). |
| `γ`, `γ₁` | `gamma`, `gamma1` | Anchura de la máscara uniforme. |
| `γ₂` | `gamma2` | Medio paso de redondeo (`α = 2γ₂`). |
| `β` | `beta` | Cota de `‖testigo·c‖∞`. |
| `c̃`, `c` | `c` / `challenge_seed` | Semilla del desafío (32 bytes) y desafío derivado. |
| `w`, `w₁` | `commitment`, `high_bits` | Compromiso y sus bits altos. |
| `z` | `z1`, `z2`, `response` | Respuesta enmascarada. |
| `ν` | `nu` | Marca de tiempo del reto, en milisegundos. |
| `id_C` | `public_key_digest`, `client_id` | `H(t)`, identificador del cliente en ML-ZKAuth. |
| `vpk`, `vsk` | `vpk`, `private_seed` | Par ML-KEM-768 del verificador. |
| `K` | `token_key` | Secreto encapsulado en `tok1`. |

## Anexo B. Formato y tamaño de los artefactos

Tamaños medidos en la corrida oficial, en JSON canónico (bytes). Los campos binarios van en Base64.

| Candidato | `system_parameters` | Clave pública | Clave privada | Reto | Respuesta |
|---|---|---|---|---|---|
| `ecdsa` | `{}` · 0 | `{key_pem}` · 254 | `{key_pem}` · 338 | `{nonce}` · 56 | `{signature}` · ≈ 112 (varía con la firma DER) |
| `standard_lwe` | `{protocol, parameters, matrix_a}` · 6 642 953 | `{B}` · 761 864 | `{S, E, public_key_digest}` · 381 010 | `{nonce}` · 56 | `{c, z1, z2}` · 11 972 |
| `binary_lwe` | ídem · 7 629 396 | `{B}` · 816 480 | `{S, E, public_key_digest}` · 229 718 | `{nonce}` · 56 | `{c, z1, z2}` · 12 828 |
| `ring_lwe` | `{protocol, parameters, a}` · 6 002 | `{b}` · 5 472 | `{s, e, public_key_digest}` · 2 818 | `{nonce}` · 56 | `{c, z1, z2}` · 10 996 |
| `lwr` | `{protocol, parameters, matrix_a}` · 6 595 459 | `{B}` (mod `p`) · 759 136 | `{S, E, public_key_digest}` · 379 650 | `{nonce}` · 56 | `{c, z1, z2}` · 11 932 |
| `proposed_lwe` | `{protocol, parameters, rho, vpk}` · 2 262 | `{t}` · 3 936 | `{s, e, public_key_digest}` · 1 450 | `{ticket, nu}` · 76 | `{tok1, tok2}` · 4 721 |

Codificaciones: los candidatos de la plantilla común usan ancho mínimo por coeficiente (1, 2 o 4 bytes), y la decodificación de `z` con desplazamiento hace de comprobación de norma. ML-ZKAuth usa empaquetado de bits: 23 bits para `t`, 18 para `z`, 4 para `s` y `e`, 12 para las cuotas del acuerdo de clave y 6 para `w₁` dentro del hash.
