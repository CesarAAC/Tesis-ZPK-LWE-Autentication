# Estimación de dureza de los candidatos

Este documento explica cómo se estima la seguridad de cada candidato, qué parámetros se eligieron para que los cinco candidatos de retículos alcancen 128 bits en el modelo Core-SVP y cómo repetir el cálculo. Las cifras corresponden a `backend/benchmarking/configs/default.json` del 4 de octubre de 2026.

## Resultado

Los cinco candidatos de retículos quedan entre 2^128.0 y 2^128.6 en Core-SVP clásico y entre 2^116.3 y 2^117.9 en cuántico. En los cinco limita la clave, no la solidez de la prueba.

| Candidato | Parámetros que cambian | Clave: ataque y bloque b | Clave: clásico / cuántico | Solidez: b, clásico | Autenticación |
|---|---|---|---|---|---|
| `proposed_lwe` | `k_proof = 4`, `eta_proof = 6` | primal, 439 | 2^128.2 / 2^116.3 | 516, 2^150.7 | 2^128.2 / 2^116.3 |
| `standard_lwe` | `n = m = 1116` | dual híbrido, 438 | 2^128.0 / 2^116.9 | 577, 2^168.5 | 2^128.0 / 2^116.9 |
| `ring_lwe` | `η = 6` (`n = 1024`) | primal, 439 | 2^128.2 / 2^116.3 | 516, 2^150.7 | 2^128.2 / 2^116.3 |
| `binary_lwe` | `n = m = 1196` | dual híbrido, 440 | 2^128.5 / 2^117.9 | 631, 2^184.3 | 2^128.5 / 2^117.9 |
| `lwr` | `n = m = 1112`, `p = 2^21` | dual híbrido, 440 | 2^128.6 / 2^117.4 | 575, 2^167.9 | 2^128.6 / 2^117.4 |
| `ecdsa` | ninguno (P-256) | — | 2^128 / roto | — | 2^128 / roto |

La columna «Autenticación» es el mínimo entre la clave y la solidez.

**Qué significa y qué no.** 128 bits Core-SVP es un objetivo más exigente que el que cumplen los esquemas que NIST clasifica en el nivel 1: ML-KEM-512 tiene 2^118 en Core-SVP y NIST lo acepta en la categoría 1 porque su coste refinado es de unas 2^151 compuertas. Ninguna estimación garantiza una categoría de NIST: la categoría 1 se define como «al menos tan difícil como buscar una clave de AES-128» (unas 2^143 compuertas clásicas), y se juzga con análisis refinados. Lo que estas cifras afirman es que, con la misma herramienta y el mismo modelo, los cinco candidatos tienen la misma dureza estimada y que esa dureza no es menor que 2^128.

ECDSA no puede igualarse: P-256 da 128 bits clásicos (NIST SP 800-57 parte 1, rev. 5) y el algoritmo de Shor lo rompe en tiempo polinomial. Es la línea base clásica.

La capa de transporte de `proposed_lwe` (cuotas del acuerdo de clave sobre `q = 3329` con `η = 2`, del tamaño de ML-KEM-768) está en 2^174.3 y no limita la autenticación.

## Métrica: Core-SVP

Todas las cifras de retículos usan el modelo Core-SVP de Alkim, Ducas, Pöppelmann y Schwabe (2016), el mismo de las especificaciones de Kyber y Dilithium:

- Un ataque se resume en el tamaño de bloque `b` de BKZ que necesita.
- Su coste es el de una sola llamada a SVP en dimensión `b` por criba: 2^(0.292·b) clásico y 2^(0.265·b) cuántico.
- La forma de la base reducida sigue la hipótesis geométrica (GSA).

Core-SVP es una cota inferior conservadora y sirve para comparar. No es el coste real: ignora el número de llamadas, la memoria y las mejoras de criba posteriores.

## Herramienta

[lattice-estimator](https://github.com/malb/lattice-estimator), commit `53da5982597709ba0fdf94ea37a84d822310fd84` (19 de agosto de 2026), con el modelo de coste `ADPS16` (clásico y cuántico).

- **LWE:** ataque primal (uSVP) y ataque dual híbrido, los mismos de `LWE.estimate.rough`. Se informa el más barato.
- **SIS en norma infinito:** `SIS.lattice`, el ataque de las especificaciones de Dilithium.
- Para comprobar que no hay un ataque mejor, se corrió también el catálogo completo (`LWE.estimate` con `ADPS16`: BKW, Arora-GB, BDD, BDD híbrido, BDD con MITM, dual y dual híbrido) sobre las instancias de `standard_lwe`, `binary_lwe` y `lwr` de dimensión cercana. Ninguno fue más barato que el primal o el dual híbrido; los híbridos con MITM sobre el secreto binario costaron más de 2^165.

### Validación

Antes de usarla se comprobó que la herramienta reproduce los tamaños de bloque que publican Kyber y Dilithium (especificaciones de ronda 3):

| Instancia | Publicado | lattice-estimator |
|---|---|---|
| Kyber512, primal | 406 (2^118) | 406 (2^118.6) |
| Kyber768, primal | 625 | 624 |
| Dilithium2, LWE primal | 423 | 424 |
| Dilithium2, SIS | 423 | 423 |

Además, una reimplementación independiente de los scripts de [pq-crystals/security-estimates](https://github.com/pq-crystals/security-estimates) da los mismos tamaños de bloque para el ataque primal y reproduce exactamente los de Dilithium 2, 3 y 5.

## Qué problema se estima en cada candidato

Cada candidato se reduce a dos instancias: la de la **clave** (que la clave pública sea indistinguible de aleatoria) y la de la **solidez** (que nadie produzca una prueba aceptada sin conocer un testigo). `backend/benchmarking/hardness.py` construye ambas a partir de los parámetros efectivos que resuelve el propio protocolo.

### Clave

| Candidato | Relación | Instancia estimada |
|---|---|---|
| `proposed_lwe` | `t = A'·s + e mod q'`, `A' ∈ R_q'^{k'×k'}` | LWE de dimensión `n = k'·d = 1024`, `m = 1024` muestras, `q' = 8380417`, secreto y error `CBD(6)` |
| `standard_lwe` | `B = A·S + E mod q`, `S` con ℓ columnas | LWE `n = m = 1116`, `q = 8380417`, secreto y error `CBD(2)` |
| `binary_lwe` | igual, `S ∈ {0, 1}` | LWE `n = m = 1196`, secreto uniforme en `{0, 1}`, error `CBD(2)` |
| `lwr` | `B = ⌊(p/q)·A·S⌉` | LWE `n = m = 1112`, `q = 2^23`, secreto `CBD(2)`, error uniforme en `{−1, 0, 1, 2}` |
| `ring_lwe` | `b = a·s + e` en `Z_q[x]/(x^n + 1)` | LWE `n = m = 1024`, `q = 8380417`, secreto y error `CBD(6)` |

Decisiones de modelado, las mismas que usan los diseñadores de esos esquemas:

- **MLWE y Ring-LWE se estiman como LWE** de la misma dimensión. No se conoce un ataque que aproveche la estructura algebraica a estos tamaños; así lo hacen Kyber, Dilithium y Saber.
- **Las ℓ columnas de `S` comparten `A`.** Atacar una columna es una instancia LWE de dimensión `n`; tener ℓ de ellas no abarata el ataque de forma conocida.
- **LWR se estima como LWE con error uniforme** sobre el intervalo de redondeo, que para `q/p = 4` es `{−1, 0, 1, 2}` (el test `test_lwr_error_interval_matches_the_rounding_of_the_implementation` comprueba que el intervalo coincide con el redondeo del código). Es la heurística habitual para Saber; la reducción formal de LWR a LWE pierde mucho más.
- **El secreto binario** tiene media 1/2 y varianza 1/4. El estimador lo trata con el reescalado de Bai y Galbraith, que aprovecha que el secreto es más corto que el error. Por eso `binary_lwe` necesita una dimensión mayor.

### Solidez

Las pruebas son Fiat–Shamir con abortos. Un falsificador que gana sin conocer el secreto da una solución de SelfTargetSIS (Kiltz, Lyubashevsky y Schaffner, 2018): un vector corto `x` con `H(μ, M·x) = c`. Se estima como SIS en norma infinito, igual que Dilithium:

| Candidato | Matriz `M` | Filas × columnas | Cota de `‖x‖∞` |
|---|---|---|---|
| `proposed_lwe` | `[A' | I | t]` | 1024 × 2304 | `max(γ₁ − β, γ₂ + 1) = 131 072 − 138 = 130 934` |
| `standard_lwe` | `[A | I | B]` | `m × (n + m + ℓ)` = 1116 × 2360 | `γ − κ·η = 131 010` |
| `binary_lwe` | `[A | I | B]` | 1196 × 2520 | `γ − κ = 131 041` |
| `lwr` | `[A | I | B̃]` | 1112 × 2352 | `max(γ − κ·η, γ − κ·q/2p) = 131 010` |
| `ring_lwe` | `[a | 1 | b]` | 1024 × 3072 | `γ − κ·η = 131 072 − 96 = 130 976` |

La cota es la norma de una respuesta aceptada: lo que el verificador deja pasar. En los cinco la solidez queda al menos 22 bits por encima de la clave, así que no limita.

## Cómo se ajustaron los parámetros

Objetivo: al menos 2^128 Core-SVP clásico para la autenticación de cada candidato, con la menor holgura posible para que sigan siendo comparables.

1. **`proposed_lwe`.** Con `η = 2` el rango solo da 2^114.9 (`k_proof = 4`) o 2^152.4 (`k_proof = 5`), y `q'` está fijado. Un rectángulo 4×5 da lo mismo que el rango 5. Los autores eligieron (4 de octubre de 2026) mantener el rango 4 y ensanchar el ruido de la clave de identidad a `CBD(6)`: 2^128.2. Solo cambia la capa de prueba; la de transporte sigue con `η = 2`. Con `β = η'·κ = 138`, un intento del probador se publica con probabilidad 0.077, unos 13 intentos por prueba. Usar los `γ₁` y `γ₂` de ML-DSA-65 acelera el probador (0.44) pero baja la solidez a 2^115, así que se descartó.
2. **`standard_lwe`.** Con `n = m = 1024` daba 2^114.9. 1112 da 2^127.5 y 1116 da 2^128.0: se eligió 1116.
3. **`binary_lwe`.** 1192 da 2^127.95, apenas por debajo; 1196 da 2^128.5.
4. **`lwr`.** Con `p = 2^21` el error de redondeo queda en `{−1, …, 2}` y la cota del testigo en 2, igual que `η`: la prueba usa la misma `β` que `standard_lwe`. 1108 da 2^127.996, apenas por debajo; 1112 da 2^128.6.
5. **`ring_lwe`.** `n` debe ser potencia de 2: 1024 da 2^114.9 y 2048 se va muy por encima. Se subió el ruido: `η = 5` da 2^126.1 y `η = 6` da 2^128.2.
6. Los parámetros de las pruebas (`ℓ = 128`, `κ`, `γ = 2^17`, y `γ₁`, `γ₂` en `proposed_lwe`) no cambian: la solidez queda por encima de la clave sin tocarlos.

El objetivo fue igualar la dureza estimada, no las dimensiones: con la misma dimensión un candidato sería más débil y otro más fuerte que el resto, y la comparación de tiempos y tamaños favorecería a uno.

## Tamaños y tiempos con estos parámetros

Corrida exploratoria de 60 autenticaciones por candidato (mediana), no evidencia de tesis. Tamaños en JSON canónico, lo que mide el runner.

| Candidato | `system_parameters` | Clave pública | Clave privada | Respuesta | Autenticación |
|---|---|---|---|---|---|
| `proposed_lwe` | 2 262 B | 3 936 B | 1 450 B | 4 721 B | 6.7 ms |
| `ring_lwe` | 6 002 B | 5 472 B | 2 818 B | 10 996 B | 4.2 ms |
| `standard_lwe` | 6.64 MB | 762 KB | 381 KB | 11 972 B | 14.2 ms |
| `lwr` | 6.60 MB | 759 KB | 380 KB | 11 932 B | 13.9 ms |
| `binary_lwe` | 7.63 MB | 816 KB | 230 KB | 12 828 B | 15.4 ms |

El tiempo de `proposed_lwe` sube de 2.4 ms a 6.7 ms por los reintentos del probador con `η' = 6`. Su respuesta creció 40 bytes (32 crudos) el 7 de octubre de 2026, cuando el identificador del cliente pasó a viajar dentro de `tok2`; el tiempo es de la corrida anterior a ese cambio.

## Cómo repetir el cálculo

Desde `lwe-auth-project/`, en Git Bash:

```bash
git clone https://github.com/malb/lattice-estimator.git ../lattice-estimator
git -C ../lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84

MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps -T \
  -v "$(cd ../lattice-estimator && pwd -W)":/estimator \
  benchmark sage -python -m benchmarking.hardness_cli \
  --output-dir benchmark-results/hardness
```

`pwd -W` da la ruta de Windows que necesita Docker Desktop; en Linux o macOS basta `$(cd ../lattice-estimator && pwd)`. Tarda varios minutos.

La salida imprime, por candidato, cada ataque con su bloque y su coste, y el mínimo. En `backend/benchmark-results/hardness/` deja:

- `<protocolo>.security.json`: un *security assessment* con el formato de `configs/security.template.json` (herramienta, commit, parámetros, modelo de coste y supuestos).
- `<protocolo>.raw.json`: el detalle por instancia y ataque.

Para asociarlos a una corrida del benchmark:

```bash
docker compose run --rm -T benchmark sage -python -m benchmarking.security_cli \
  --run-id <RUN_UUID> --file benchmark-results/hardness/<protocolo>.security.json
```

Con el estimador montado en `/estimator`, `tests/test_hardness.py` además comprueba que se reproducen Kyber512 y Dilithium2, que cada instancia de cada candidato llega a 2^128 y que ninguna clave pasa de 2^129. Sin él, esos tests se saltan.

Si se cambia un parámetro en `default.json`, el cálculo usa el nuevo valor automáticamente: `hardness_cli` resuelve los parámetros con el propio protocolo.

### Búsqueda del rango y del ruido de `proposed_lwe`

La tabla del capítulo 4 de la tesis con la búsqueda de `(k_proof, eta_proof)` se reproduce con `make proof-layer-search` (o `./scripts/proof-layer-search.sh`). El script clona el estimador en `../lattice-estimator` en el commit indicado arriba si no está (o usa `LATTICE_ESTIMATOR_DIR`), lo monta en `/estimator` y ejecuta `python -m benchmarking.proof_layer_search` en el contenedor. Por cada par imprime la dureza de la clave (misma instancia y mismos ataques que `hardness_cli`), la probabilidad de aceptación por intento y los intentos medios. Con `--without-hardness` calcula solo las dos últimas columnas y no necesita el estimador.

## Límites

- **Core-SVP es una cota para comparar, no un coste.** Las estimaciones refinadas (número de llamadas, memoria, *dimensions for free*) suben el coste clásico unos 30 a 40 bits: Kyber512 pasa de 2^118 a 2^151.5 compuertas y Dilithium2 de 2^123 a 2^159.
- **La estructura algebraica no se modela.** MLWE y Ring-LWE se tratan como LWE.
- **LWR se modela como LWE** con error uniforme; es heurístico.
- **La solidez se estima como SelfTargetSIS en el modelo de oráculo aleatorio.** El oráculo aleatorio cuántico no está analizado.
- **Canales laterales y tiempo constante quedan fuera:** las implementaciones usan NumPy.
- **ECDSA** se cita de la literatura; no se estima.

## Referencias

- Alkim, Ducas, Pöppelmann, Schwabe. *Post-quantum key exchange — a new hope*. USENIX Security 2016 (modelo Core-SVP).
- [CRYSTALS-Kyber, especificación de ronda 3](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf), sección 5.1.
- [CRYSTALS-Dilithium, especificación de ronda 3](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf), Tablas 1 a 3 y sección 6.
- Kiltz, Lyubashevsky, Schaffner. *A concrete treatment of Fiat-Shamir signatures in the quantum random-oracle model*. EUROCRYPT 2018 (SelfTargetMSIS).
- Bai, Galbraith. *Lattice decoding attacks on binary LWE*. ACISP 2014 (reescalado para secretos pequeños).
- Albrecht, Player, Scott. *On the concrete hardness of Learning with Errors*. Journal of Mathematical Cryptology, 2015 (base del lattice-estimator).
- D'Anvers, Karmakar, Sinha Roy, Vercauteren. *Saber: Module-LWR based key exchange, CPA-secure encryption and CCA-secure KEM*. AFRICACRYPT 2018 (esquema LWR cuya seguridad se estima tratando el redondeo como error uniforme).
- NIST SP 800-57 parte 1, rev. 5 (P-256: 128 bits).
- NIST, *Submission Requirements and Evaluation Criteria for the Post-Quantum Cryptography Standardization Process* (2016), sección 4.A.5 (definición de las categorías de seguridad).
