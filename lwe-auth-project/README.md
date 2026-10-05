# LWE Authentication Benchmark

Repositorio experimental para comparar, bajo una metodología común y reproducible, seis candidatos de autenticación:

1. `ecdsa` — ECDSA P-256, baseline tradicional.
2. `standard_lwe` — identificación Fiat–Shamir con abortos (NIZK) sobre LWE (secreto binomial centrado).
3. `binary_lwe` — identificación Fiat–Shamir con abortos (NIZK) sobre LWE con secreto binario.
4. `ring_lwe` — identificación Fiat–Shamir con abortos (NIZK) sobre Ring-LWE en $Z_q[x]/(x^n+1)$.
5. `lwr` — identificación Fiat–Shamir con abortos (NIZK) sobre Learning With Rounding (LWR).
6. `proposed_lwe` — PQLite-Auth v2, el protocolo diseñado en la tesis: prueba Fiat–Shamir con abortos sobre MLWE con módulo `q' = 8380417`, y sobre `q = 3329` el token oculto con ML-KEM-768 + AES-256-GCM, los tickets de un solo uso y el acuerdo de clave de sesión.

El objetivo del repositorio no es producir un “ganador” automático. El framework registra evidencia comparable sobre rendimiento, memoria, tamaños serializados, comunicación, almacenamiento, comportamiento proyectado bajo distintas redes, complejidad de implementación y metadatos de reproducibilidad. Las afirmaciones de seguridad, madurez y arquitectura se almacenan aparte y deben incluir evidencia explícita.

> **Regla principal:** una primitiva matemática no se registra como protocolo completo. Un candidato solo queda disponible para benchmarking cuando implementa el ciclo completo de autenticación y supera las pruebas de conformidad comunes.

---

## Estado actual

- Implementados completamente los seis candidatos: `ecdsa`, `standard_lwe`, `binary_lwe`, `ring_lwe`, `lwr` y `proposed_lwe`.
- Los cuatro candidatos de retículos son identificación **Fiat–Shamir con abortos**: pruebas no interactivas de conocimiento cero en el modelo de oráculo aleatorio programable; ver [Candidatos de retículos](#candidatos-de-retículos-identificación-fiatshamir-con-abortos).
- `backend/crypto_core/lwe/` contiene primitivas reutilizables (muestreo con CSPRNG, codificación, aritmética negacíclica y de módulos, redondeo LWR, descomposición en bits altos y bajos, reconciliación de Peikert y helpers Sage de keygen); no son protocolos de autenticación por sí solas. `backend/crypto_core/token_hiding.py` envuelve ML-KEM-768 y AES-256-GCM.
- `proposed_lwe` implementa PQLite-Auth v2 con módulo dual. Su prueba es una NIZK en el modelo de oráculo aleatorio programable, también frente al verificador designado. Con el rango del manuscrito (`k_proof = 3`) la dureza estimada de la clave de identidad queda **por debajo del objetivo de 128 bits**, y varias definiciones tuvieron que fijarse; ver [Protocolo propuesto](#protocolo-propuesto-pqlite-auth-v2-proposed_lwe).
- Una entrada del catálogo sin `implementation_factory` sigue fallando de forma cerrada.
- Los parámetros por defecto son experimentales; su nivel de seguridad debe estimarse y documentarse por separado antes de usarlos como evidencia de tesis.
- Ya están preparados el contrato común, benchmark runner, pruebas de conformidad, mediciones, exportación JSON/CSV, persistencia PostgreSQL, proyecciones de red y formatos para assessments cualitativos y estimaciones de seguridad.

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

# Candidatos de retículos: identificación Fiat–Shamir con abortos

`standard_lwe`, `binary_lwe`, `ring_lwe` y `lwr` usan **el mismo sistema de prueba** (`backend/crypto_core/protocols/lattice_zk.py`): el esquema de identificación *Fiat–Shamir con abortos* de Lyubashevsky (2012), en su variante LWE (se envían `z1` y `z2`; la clave tiene `ℓ` columnas secretas). **No es Dilithium:** no usa la descomposición HighBits/LowBits de `w`, hints, la segunda condición de rechazo ni la clave pública comprimida; solo los tamaños de parámetros siguen a Dilithium2. Solo cambia la relación lineal probada, así que las diferencias medidas se atribuyen al supuesto de retículos.

## Relación y mapeo al contrato

El probador posee `(S, E)` cortos tales que `A·S + E = B̃ (mod q)`; lo que la prueba garantiza se precisa en [Propiedades](#propiedades-enunciadas-con-precisión).

| Candidato | Archivo | Setup compartido | Secreto `S` | Error `E` | `B̃` (clave pública elevada a `Z_q`) |
|---|---|---|---|---|---|
| `standard_lwe` | `lwe_zk.py` | `A ∈ Z_q^{m×n}` | binomial centrado `η`, `n×ℓ` | binomial centrado `η` | `B = A·S + E` |
| `binary_lwe` | `lwe_zk.py` | `A ∈ Z_q^{m×n}` | `{0,1}^{n×ℓ}` | binomial centrado `η` | `B = A·S + E` |
| `lwr` | `lwr_auth.py` | `A ∈ Z_q^{m×n}` | binomial centrado `η`, `n×ℓ` | redondeo determinista, `‖E‖∞ ≤ q/2p` | `(q/p)·B`, con `B = ⌊(p/q)·A·S⌉ mod p` |
| `ring_lwe` | `ring_lwe.py` | `a ∈ Z_q[x]/(xⁿ+1)` | binomial centrado `η` | binomial centrado `η` | `b = a·s + e` |

Los tres candidatos matriciales comparten `matrix_lwe_zk.py`.

```text
generate_challenge  (verificador):  nonce <- 32 bytes aleatorios
solve_challenge     (probador):     repetir:
                                        y1, y2 <- U([-γ, γ])                 (máscaras)
                                        w  = A·y1 + y2 mod q                  (compromiso)
                                        c~ = H(params, H(pk), nonce, w)       (Fiat–Shamir)
                                        c  = ternario disperso(c~), peso κ
                                        z1 = y1 + S·c,  z2 = y2 + E·c
                                    hasta que ‖z_i‖∞ <= γ - β_i   (β_i = κ·‖testigo_i‖∞)
                                    respuesta = (c~, z1, z2)
verify_response     (verificador):  normas OK  y  H(params, H(pk), nonce, A·z1 + z2 - B̃·c) == c~
```

## Propiedades (enunciadas con precisión)

No se afirma nada más allá de lo siguiente.

- **Conocimiento cero.** El protocolo interactivo subyacente es *non-abort special honest-verifier zero knowledge*. Su versión Fiat–Shamir es un **NIZK en el modelo de oráculo aleatorio programable**: el simulador elige `c~`, deriva `c`, elige `z` uniforme en `[-(γ-β), γ-β]`, fija `w = A·z1 + z2 − B̃·c` y programa `H(params, H(pk), nonce, w) = c~`. Coincide con las transcripciones reales porque `‖testigo·c‖∞ ≤ β`: un `z` aceptado es uniforme en esa caja sea cual sea el secreto, y la probabilidad de aceptación por intento depende solo de `γ`, `β` y las dimensiones. Los intentos abortados nunca se envían. **No analizado:** el modelo de oráculo aleatorio cuántico (QROM) ni canales laterales de tiempo.
- **Argumento de conocimiento de una relación relajada, no de `(S, E)`.** Dos transcripciones aceptadas con el mismo `w` y `c ≠ c'` dan `(z1 − z1', z2 − z2', c − c')` cortos con `A·(z1 − z1') + (z2 − z2') = B̃·(c − c') (mod q)` (*forking lemma*). Ese testigo no es `S` ni `E` (un `S` binario no sigue siendo binario). La seguridad contra suplantación se apoya en que la clave sea pseudoaleatoria (LWE, Ring-LWE o LWR) y en la dificultad de SIS para `[A | I | −B̃]` con norma `2·(γ − β)`; ambas deben estimarse para los parámetros usados.
- **Frescura y binding:** el nonce y `H(pk)` entran en el hash, por lo que una respuesta no verifica bajo otro desafío ni bajo otra clave pública.
- **Verificación sin estado:** el verificador ya no necesita guardar el desafío completo, solo recordar qué nonces emitió para impedir replay entre sesiones.
- **No es negable:** la prueba es no interactiva y por lo tanto transferible (como una firma).
- Las pruebas automáticas incluyen chequeos estadísticos de que `z` es uniforme en la caja; no constituyen una demostración formal.

## Decisiones de diseño

- **Secreto corto.** Fiat–Shamir con abortos requiere un testigo corto para enmascararlo. Por eso `standard_lwe` y `lwr` usan secreto binomial centrado (LWE en forma normal, misma familia de dificultad) en lugar de uniforme en `Z_q`.
- **LWR como relación exacta.** Con `x = A·S mod q` y `B = ⌊(p·x + q/2)/q⌋ mod p`, el error determinista `E = (q/p)·B − x` (centrado mod `q`) cumple `A·S + E = B̃` con `‖E‖∞ ≤ q/2p`, incluso cuando el redondeo llega a `p` y se reduce a 0; `test_rounding_error_satisfies_lifted_relation` verifica relación y cota. El conocimiento cero solo necesita esa cota, no la distribución de `E`. La clave es una instancia **LWR con secreto corto**, no LWE: su dificultad debe estimarse como LWR; tratar el redondeo como ruido LWE de desviación ≈ `(q/p)/√12` es solo una heurística.
- **ℓ columnas secretas en los candidatos matriciales.** Con un solo vector secreto el espacio de desafíos es pequeño y harían falta ~128 repeticiones. Con `ℓ = 128` columnas y un desafío ternario de peso `κ = 31` el espacio es de 129.6 bits en una sola ronda. `ring_lwe` no lo necesita: el desafío es un polinomio con `κ = 16` coeficientes `±1` (131.6 bits).
- **Módulo grande.** La solidez exige `q ≫ γ`; se valida `q >= 16·γ`. Con `γ = 2^17` esto obliga a `q ≈ 2^23` (codificación de 4 bytes por coeficiente).
- **Validación de parámetros.** `resolve_parameters()` rechaza espacios de desafío menores a 128 bits, `γ <= β` (no ocultaría el secreto) y probabilidades de aceptación por intento menores a 5 %.
- **Aleatoriedad.** Máscaras y claves usan `secrets.token_bytes`; el desafío se expande desde `c~` con SHAKE-256 (muestreado como `SampleInBall` de Dilithium).
- **Serialización.** Ancho mínimo por coeficiente (1, 2 o 4 bytes, little-endian, Base64); `z` se codifica con desplazamiento, por lo que cualquier coeficiente fuera de la cota se rechaza al decodificar. El secreto binario se empaqueta a 1 bit.
- `ring_lwe` usa convolución negacíclica directa `O(n²)`, no NTT.

## Parámetros por defecto y tamaños

| Candidato | Parámetros | Referencia |
|---|---|---|
| `standard_lwe`, `binary_lwe` | `n = m = 1024`, `q = 8380417`, `η = 2`, `ℓ = 128`, `κ = 31`, `γ = 2^17` | tamaños como Dilithium2 |
| `lwr` | `n = m = 1024`, `q = 2^23`, `p = 2^20` (`‖E‖∞ ≤ 4`), `η = 2`, `ℓ = 128`, `κ = 31`, `γ = 2^17` | mismas dimensiones |
| `ring_lwe` | `n = 1024`, `q = 8380417`, `η = 2`, `κ = 16`, `γ = 2^17` | tamaños como Dilithium2 |

| | `system_parameters` | clave pública | clave privada | desafío | respuesta |
|---|---|---|---|---|---|
| `standard_lwe`, `lwr` | ≈ 5.6 MB | ≈ 700 KB | ≈ 350 KB | 56 B | ≈ 11 KB |
| `binary_lwe` | ≈ 5.6 MB | ≈ 700 KB | ≈ 197 KB | 56 B | ≈ 11 KB |
| `ring_lwe` | ≈ 6 KB | ≈ 5.5 KB | ≈ 2.8 KB | 56 B | ≈ 11 KB |

> **Advertencia:** estos parámetros son un punto de partida, no una demostración de seguridad. La dificultad de LWE/LWR (en particular con secreto binario) y la solidez de la prueba deben estimarse (p. ej. con lattice-estimator) y registrarse con `security_cli` antes de usar resultados en la tesis.

**Métrica de líneas de código.** `code_metrics.py` cuenta el archivo de la clase registrada más los archivos de sus clases base dentro de `crypto_core/` (excepto `interface.py`); por eso cada candidato incluye `lattice_zk.py` (y los matriciales también `matrix_lwe_zk.py`). Los módulos auxiliares solo importados (`crypto_core/lwe/`) no se cuentan.

---

# Protocolo propuesto: PQLite-Auth v2 (`proposed_lwe`)

Implementado en `backend/crypto_core/protocols/proposed_lwe.py`. Tiene dos fuentes de verdad criptográficas: `Document/capitulos/04-Protocolo Propio.tex` y la instrucción de **módulo dual** de los autores (su «Opción A»), que sustituye la prueba del capítulo por Fiat–Shamir con abortos sobre un segundo módulo. Donde difieren, manda la instrucción. Supera el *conformance gate* sin modificarlo y entra al benchmark como los demás candidatos.

> **Decisión pendiente de los autores: el rango de la capa de prueba.** Con el rango del manuscrito (`k_proof = 3`) la clave de identidad es una instancia MLWE de dimensión 768 sobre un módulo de 23 bits. La metodología Core-SVP la sitúa en torno a 2^79 operaciones clásicas (2^72 cuánticas): por debajo del nivel 1 de NIST que declara el manuscrito y por debajo de los otros candidatos de retículos de este repositorio (dimensión 1024, en torno a 2^117). Con `k_proof = 4` queda en torno a 2^117 clásicas y 2^106 cuánticas. El valor por defecto sigue siendo 3 porque es el que fija el manuscrito y la instrucción no lo cambió; pasar a 4 es un parámetro. Ver [Estimación de dureza de la capa de prueba](#estimación-de-dureza-de-la-capa-de-prueba).

## Dos capas

| Capa | Módulo | Qué vive ahí |
|---|---|---|
| Prueba | `q' = 8380417` (23 bits, el primo de ML-DSA) | Clave de identidad `t = A'·s + e` y la prueba de conocimiento. |
| Transporte | `q = 3329` (manuscrito) | Ocultación del token con ML-KEM-768 + AES-256-GCM y acuerdo de clave de sesión con reconciliación de Peikert. |

La prueba no cabe en `q = 3329` (`DualModulusRationaleTests`): para que el muestreo de rechazo independice la respuesta del secreto hace falta una máscara de anchura `γ₁ ≈ 15 400` (10 % de aceptación con 768 coeficientes y `β = 46`), frente a `q/2 = 1664`; y entre los pasos de redondeo que dividen a `q − 1`, el mejor da una aceptación de 6.6·10⁻²⁰ para la condición de bits bajos.

## Flujo y mapeo al contrato

`k'` es `k_proof`, `α = 2·γ₂` y `β = eta · kappa`.

| Contrato | PQLite-Auth v2 |
|---|---|
| `generate_system_parameters` | `rho` (32 bytes) y par ML-KEM-768 del verificador. `system_parameters = {rho, vpk}`. `A' ∈ R_q'^{k'×k'}` y `A ∈ R_q^{3×3}` se expanden con SHAKE-128 desde semillas distintas derivadas de `rho`. `vsk` queda en el almacén del proceso. |
| `generate_keypair` | `s, e ← CBD(2)^{k'}`, `t = A'·s + e mod q'`. Clave pública `t` (2208 B). Clave privada `s` y `e` (288 B cada una) más `H(t)` (32 B). |
| `generate_challenge` | El verificador emite un ticket de un solo uso (256 bits) y la marca de tiempo `nu`. |
| `solve_challenge` | `y` uniforme en `[−(γ₁−1), γ₁−1]`, `w = A'·y`, `w₁ = HighBits(w, α)`, `c̃ = H(A', t, w₁, ticket, nu)`, `c = SampleInBall(c̃)`, `z = y + c·s`. Reintenta si `‖z‖∞ ≥ γ₁ − β` o si `‖LowBits(w − c·e, α)‖∞ ≥ γ₂ − β`. Token: `tok1` = cifrado ML-KEM-768, `tok2 = AES-256-GCM_K(z, c̃, ticket, nu)`. |
| `verify_response` | Descifra, ventana temporal, registro de tickets consumidos, exige `‖z‖∞ < γ₁ − β`, calcula `w₁' = HighBits(A'·z − c·t, α)` y acepta si `H(A', t, w₁', ticket, nu) = c̃`. Devuelve `bool`. |
| Fuera del contrato | `generate_key_agreement_share`, `generate_reconciliation_hint`, `reconcile_session_key`: acuerdo de clave de sesión por reconciliación de Peikert sobre `q = 3329`. |

**Por qué una prueba honesta siempre verifica.** `A'·z − c·t = A'·y + c·A'·s − c·(A'·s + e) = w − c·e`. Como `‖c·e‖∞ ≤ β` y el probador solo publica `z` cuando `‖LowBits(w − c·e)‖∞ < γ₂ − β`, sumar `c·e` no cambia los bits altos: `HighBits(w − c·e) = HighBits(w) = w₁`, y el verificador calcula el hash sobre la misma entrada. No hay error de completitud; lo único aleatorio es cuántos intentos necesita el probador. Medido: 20 000 de 20 000 autenticaciones honestas aceptadas con 40 claves (`k_proof = 3`) y 10 000 de 10 000 con 20 claves (`k_proof = 4`).

## Parámetros

Fijos; cualquier otro valor se rechaza: `d = 256`, `k = 3`, `q = 3329`, `eta = 2` (manuscrito) y `q_proof = 8380417` (instrucción de módulo dual).

Ni el manuscrito ni la instrucción fijan los siguientes. Son ajustables en `benchmarking/configs/default.json`:

| Parámetro | Por defecto | Origen del valor |
|---|---|---|
| `k_proof` | 3 | Rango de la capa de prueba; el `k` del manuscrito. Admite de 3 a 8. |
| `kappa` | 23 | Peso del desafío; el menor que da al menos 2^128 desafíos con `d = 256`. |
| `beta` | 46 | Derivado, no ajustable: `eta · kappa`, el máximo de `‖c·s‖∞` y `‖c·e‖∞`. |
| `gamma1` | 131072 = 2^17 | Anchura de la máscara. Valor de ML-DSA-44. |
| `gamma2` | 95232 = (q' − 1)/88 | Medio paso de redondeo; `2·gamma2` debe dividir a `q' − 1`. Valor de ML-DSA-44. |
| `time_window_seconds` | 300 | `Δt` del manuscrito. |

Probabilidad de que un intento del probador se publique:

```text
p = ((2(γ₁ − β) − 1) / (2γ₁ − 1))^(k'·d) · ((2(γ₂ − β) − 1) / (2γ₂))^(k'·d)
```

El primer factor no depende de la clave: sea cual sea `c·s`, mientras `‖c·s‖∞ ≤ β`, el mismo número de máscaras lleva a un `z` aceptado. El segundo trata `w − c·e` como uniforme. Con los valores por defecto `p = 0.764 · 0.687 = 0.525` (medido: 0.527, 1.90 intentos de media, máximo 15 en 20 000 pruebas); con `k_proof = 4`, `p = 0.423`. Un juego de parámetros con `p < 0.05` se rechaza.

## Lecturas que hubo que fijar

Ninguna es una corrección silenciosa: cada una queda registrada aquí y en el docstring del módulo, y tiene su evidencia en `tests/test_proposed_lwe.py` (`ManuscriptDeviationTests`, `DualModulusRationaleTests`).

| # | Fuente | Problema | Implementado |
|---|---|---|---|
| 1 | La instrucción cambia el módulo de la prueba; el manuscrito fija `k = 3` para `q = 3329` | El rango de la capa de prueba no está especificado, y la dureza depende de él. | `k_proof` ajustable, por defecto 3. |
| 2 | `L = H(…) ∈ R_q^{k×k}`, `z = s·L + y` | La cancelación `A(sL) − (As + e)L = −eL` exige `A·L = L·A`. Con una matriz obtenida por hash el residuo de un probador honesto es ≈ q/2. | Desafío escalar `L = c·I`. |
| 3 | `H: {0,1}* → R_q^{k×k}` sin distribución | Un `c` uniforme hace que `c·s` y `c·e` lleguen a q/2: no hay cota `β`. | `c` con `kappa` coeficientes `±1` y el resto cero, derivado con SHAKE-256. |
| 4 | `γ₁` y `γ₂` no aparecen en ninguna fuente | Parámetros necesarios. | Los de ML-DSA-44, ajustables. |
| 5 | `y ← CBD(2)`, cotas `β_z` y `β_e`, comprobación `‖A·z − t·L − w‖∞ ≤ β_e`, `w` dentro del token | Ese valor es exactamente `−c·e`: un token entrega la clave al verificador. Aun sin `w`, `z = c·s + y` con ruido acotado por 2 se resuelve por mínimos cuadrados con pocas respuestas. | Máscara uniforme ancha, las dos condiciones de rechazo y la comprobación por bits altos. `w` no viaja. |
| 6 | `Δt` sin valor | Parámetro necesario. | 300 s, ajustable. |
| 7 | No dice quién crea el ticket | El contrato exige un desafío del verificador. | El verificador emite `(ticket, nu)`; el token debe contener exactamente ese par. |
| 8 | `tok1 = Kyber.Enc(vpk, K)` con `K` elegida por el cliente | Un KEM estándar no recibe la clave: la devuelve. | `tok1` = encapsulamiento ML-KEM-768; `K` = secreto encapsulado. |
| 9 | Fórmula cerrada de `rec` | Equivale a `(⌊2w/q⌋ − v) mod 2`: no tolera ningún error. Con el ruido del propio protocolo, 99 % de las claves de 256 bits difieren. | `rec` de Peikert según la fuente citada (`w ∈ I_v + E`). |
| 10 | Tabla de cuadrantes | Asigna bit 0 a `[0, q/2)`, pero la fórmula `⌊2w/q⌉ mod 2` asigna 0 a `[−q/4, q/4)`. | Se sigue la fórmula. |
| 11 | `b_C`, `b_S`, `s_S`, `e_S`, `s_C` sin definir ni transporte | Sin ellos no hay acuerdo de clave. | Como en la fuente citada: `b_C = A·s_C + e_C`, `b_S = Aᵀ·s_S + e_S'`. El intercambio de cuotas queda a cargo de quien llama. |

Decisiones de ingeniería: aritmética NumPy con convolución negacíclica directa (no NTT ni objetos Sage; un test la contrasta con el anillo cociente de SageMath para ambos módulos); 23 bits por coeficiente para `t`, 18 para `z`, 3 para `s` y `e`, 12 en la capa de transporte; `A'` se expande desde `H(rho)` con una etiqueta propia para que no comparta flujo SHAKE con `A`; AES-256-GCM con nonce aleatorio; `H(A')` y `H(t)` como entradas del hash para que el cliente solo guarde `s`, `e` y `H(t)`; clave pública sin comprimir (sin `Power2Round` ni pistas de Dilithium).

## Estado de seguridad de `proposed_lwe`

Enunciado con precisión; no se afirma nada más.

- **Qué es la prueba.** La plantilla de Dilithium sin compresión de clave pública (Figura 1 de su especificación de ronda 3), con matriz cuadrada, secretos `CBD(2)` y `(ticket, nu)` en el lugar del mensaje.
- **Conocimiento cero.** Es una NIZK en el modelo de oráculo aleatorio programable. El simulador elige `c̃`, deriva `c`, muestrea `z` uniforme con `‖z‖∞ < γ₁ − β`, reintenta si `‖LowBits(A'·z − c·t)‖∞ ≥ γ₂ − β` y programa `H(A', t, HighBits(A'·z − c·t), ticket, nu) = c̃`. Las transcripciones reales tienen esa distribución porque `‖c·s‖∞ ≤ β` hace que un `z` aceptado sea uniforme en su caja sea cual sea `s`, y la segunda condición solo depende de `(z, c, t)`. El verificador designado ve exactamente `(z, c̃)`, así que el argumento lo cubre. Los intentos abortados nunca se envían. `ZeroKnowledgeEvidenceTests` ejecuta ese simulador y comprueba que el verificador acepta su salida cuando el oráculo está programado; es evidencia, no una demostración.
- **Solidez.** Es un argumento de conocimiento para una relación **relajada**: dos transcripciones aceptadas con el mismo `w₁` y `c ≠ c'` dan `(z − z', u, c − c')` cortos con `A'·(z − z') + u = (c − c')·t`. La resistencia a la suplantación descansa en MLWE (que `t` sea pseudoaleatorio) y en MSIS sobre `[A' | I | t]`, con el rango y el módulo de la capa de prueba.
- **No analizado:** el modelo de oráculo aleatorio cuántico y los canales laterales. El número de intentos del probador se refleja en su tiempo de ejecución, aunque su distribución no depende de la clave; NumPy no es de tiempo constante.
- **La prueba es transferible.** Una vez descifrado, `(z, c̃)` es verificable por cualquiera para ese `(ticket, nu)`: el verificador puede mostrarlo a terceros. La ocultación del token limita quién puede leer la prueba, no quién puede comprobarla.
- **Terceros** solo ven el token, protegido por ML-KEM-768 y AES-256-GCM.
- **Acuerdo de clave:** concuerda para todo error hasta 415 (hay entradas que fallan en 416, aunque q/8 = 416.125); el bit de clave tiene sesgo 1665/3329 por no usar el *doubling* de Peikert; reutilizar cuotas entre sesiones permitiría ataques de fuga de señal.

## Estimación de dureza de la capa de prueba

Core-SVP con la metodología de las especificaciones de Kyber y Dilithium (ataque primal uSVP para MLWE; ataque en norma infinito para MSIS con cota `max(γ₁ − β, γ₂ + 1) = 131026`). `b` es el tamaño de bloque BKZ; el coste es `2^(0.292·b)` clásico y `2^(0.265·b)` cuántico.

| `k_proof` | MLWE (`t = A'·s + e`) | MSIS (solidez) | Clave pública | Token | Aceptación por intento |
|---|---|---|---|---|---|
| 3 (por defecto) | `b = 270`: 2^79 / 2^72 | `b = 343`: 2^100 / 2^91 | 2208 B | 2916 B | 0.525 |
| 4 | `b = 400`: 2^117 / 2^106 | `b = 503`: 2^147 / 2^133 | 2944 B | 3492 B | 0.423 |
| 5 | `b = 535`: 2^156 / 2^142 | `b = 669`: 2^196 / 2^177 | 3680 B | 4068 B | 0.341 |
| 6 | `b = 675`: 2^197 / 2^179 | `b = 841`: 2^246 / 2^223 | 4416 B | 4644 B | 0.275 |

Referencias con la misma metodología: ML-KEM-512 `b = 406` (2^118), ML-DSA-44 `b = 423` (2^123), ML-KEM-768 `b = 625` (2^182). La especificación de Dilithium (ronda 3, Tabla 3) incluye un juego de rango 3 con `η = 3` uniforme, que llama «1-» y sitúa por debajo del nivel 1 de NIST: `b = 305`, 2^89; la capa de prueba con rango 3 y `CBD(2)` es más débil que ese juego. La capa de transporte de este protocolo (rango 3 sobre `q = 3329`) está en el nivel de ML-KEM-768; la capa de prueba no, porque el mismo ruido `CBD(2)` sobre un módulo 2500 veces mayor es una instancia más fácil. Subir `eta` casi no ayuda (`CBD(8)` con rango 3 da `b = 306`) y encarece `β`.

Estas cifras salen de una reimplementación propia de esos scripts, validada contra los tamaños de bloque publicados: reproduce exactamente los de Dilithium 2, 3 y 5 para MLWE y MSIS, con una diferencia de hasta 4 los de sus juegos «1--», «1-» y «5+», y con menos de 1 % los de Kyber. No están almacenadas como *security assessment* del repositorio: antes de usarlas como evidencia de tesis deben repetirse con el *lattice estimator* y registrarse con `benchmarking.security_cli`.

## Estado del verificador

`system_parameters` es público por contrato y el registro crea un objeto nuevo en cada llamada, así que `vsk` y el registro de tickets consumidos viven en un almacén del proceso, indexado por `H(vpk)`. Consecuencias:

- `verify_response` tiene estado: verificar dos veces el mismo token devuelve `False` la segunda vez.
- El ticket se consume antes de comprobar las ecuaciones del retículo, como indica el manuscrito; un token inválido también lo gasta.
- Un despliegue con varios procesos necesitaría un almacén compartido.

## Tamaños y tiempos medidos

| Artefacto | Bytes crudos, `k_proof = 3` | JSON canónico (lo que mide el runner) | Bytes crudos, `k_proof = 4` |
|---|---|---|---|
| `system_parameters` (`rho`, `vpk`) | 1216 | 2247 | 1216 |
| Clave pública `t` | 2208 | 2952 | 2944 |
| Clave privada (`s`, `e`, `H(t)`) | 608 | 850 | 800 |
| Desafío (`ticket`, `nu`) | 40 | 76 | 40 |
| Token (`tok1`, `tok2`) | 2916 | 3913 | 3492 |
| Cuota del acuerdo de clave `b` | 1152 | 1544 | 1152 |
| Pista de reconciliación `v` | 32 | 52 | 32 |

El token es `1088 + 12 + (1728 + 32 + 32 + 8) + 16` bytes: cifrado ML-KEM-768, nonce, `z` a 18 bits por coeficiente, `c̃`, ticket, `nu` y etiqueta de AES-GCM. Es menor que los ≈ 3.39 KB del manuscrito porque el compromiso `w` ya no viaja; a cambio la clave pública pasa de 1152 a 2208 bytes.

Corrida exploratoria de 40 iteraciones, no evidencia de tesis: enrolamiento ≈ 0.5 ms, respuesta ≈ 1.0 ms, verificación ≈ 0.6 ms, autenticación completa ≈ 1.8 ms (≈ 2.8 ms con `k_proof = 4`). El acuerdo de clave no forma parte del contrato y el runner no lo mide: generar cada cuota ≈ 0.4 ms, pista ≈ 0.2 ms, reconciliación ≈ 0.15 ms.

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

Cada verificación medida usa un desafío y una respuesta frescos, generados fuera de la región medida. Un verificador puede tener estado de un solo uso (el registro de tickets de `proposed_lwe`): repetir la misma respuesta mediría el rechazo de un replay. Si una verificación medida es rechazada, la corrida falla.

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

Con `proposed_lwe`, `/verify` tiene estado: el servidor guarda la clave de descifrado del verificador y el registro de tickets, de modo que repetir la misma petición devuelve `is_valid: false`. El acuerdo de clave de sesión no está expuesto por HTTP.

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
