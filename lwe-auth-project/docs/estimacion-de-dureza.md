# Estimación de dureza de los candidatos

Este documento explica cómo se estima la seguridad de cada candidato, qué parámetros se eligieron para que los cinco candidatos de retículos tengan la misma dureza y cómo repetir el cálculo. Las cifras corresponden a `backend/benchmarking/configs/default.json` del 4 de octubre de 2026.

## Resultado

Los cinco candidatos de retículos quedan a menos de medio bit entre sí: entre 2^114.7 y 2^115.1 en Core-SVP clásico y entre 2^104.4 y 2^105.2 en cuántico. En los cinco limita la clave, no la solidez de la prueba.

| Candidato | Parámetros que cambian | Clave: ataque y bloque b | Clave: clásico / cuántico | Solidez: b, clásico | Autenticación |
|---|---|---|---|---|---|
| `proposed_lwe` | `k_proof = 4` | dual híbrido, 393 | 2^114.9 / 2^104.7 | 516, 2^150.7 | 2^114.9 / 2^104.7 |
| `standard_lwe` | ninguno (`n = m = 1024`) | dual híbrido, 393 | 2^114.9 / 2^104.7 | 517, 2^151.0 | 2^114.9 / 2^104.7 |
| `ring_lwe` | ninguno (`n = 1024`) | dual híbrido, 393 | 2^114.9 / 2^104.7 | 516, 2^150.7 | 2^114.9 / 2^104.7 |
| `binary_lwe` | `n = m = 1096` | dual híbrido, 393 | 2^115.1 / 2^105.2 | 564, 2^164.7 | 2^115.1 / 2^105.2 |
| `lwr` | `n = m = 1016`, `p = 2^21` | dual híbrido, 392 | 2^114.7 / 2^104.4 | 511, 2^149.2 | 2^114.7 / 2^104.4 |
| `ecdsa` | ninguno (P-256) | — | 2^128 / roto | — | 2^128 / roto |

La columna «Autenticación» es el mínimo entre la clave y la solidez. El nivel coincide con el de ML-KEM-512 (2^118 por ataque primal), es decir, el orden del nivel 1 de NIST, y queda por debajo de ML-DSA-44 (2^123) porque los secretos `CBD(2)` tienen varianza 1 y los de ML-DSA-44 tienen varianza 2.

ECDSA no puede igualarse: P-256 da 128 bits clásicos (NIST SP 800-57 parte 1, rev. 5) y el algoritmo de Shor lo rompe en tiempo polinomial. Es la línea base clásica.

La capa de transporte de `proposed_lwe` (cuotas del acuerdo de clave sobre `q = 3329`, del tamaño de ML-KEM-768) está en 2^174.3 y no limita la autenticación.

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
- Para comprobar que no hay un ataque mejor, se corrió también el catálogo completo (`LWE.estimate` con `ADPS16`: BKW, Arora-GB, BDD, BDD híbrido, BDD con MITM, dual y dual híbrido) sobre `standard_lwe`, `binary_lwe` y `lwr`. En los tres el dual híbrido fue el más barato; los híbridos con MITM sobre el secreto binario costaron 2^165.8.

### Validación

Antes de usarla se comprobó que la herramienta reproduce los tamaños de bloque que publican Kyber y Dilithium (especificaciones de ronda 3):

| Instancia | Publicado | lattice-estimator |
|---|---|---|
| Kyber512, primal | 406 (2^118) | 406 (2^118.6) |
| Kyber768, primal | 625 | 624 |
| Dilithium2, LWE primal | 423 | 424 |
| Dilithium2, SIS | 423 | 423 |

Además, una reimplementación independiente de los scripts de [pq-crystals/security-estimates](https://github.com/pq-crystals/security-estimates) dio los mismos tamaños de bloque para el ataque primal (400 para la clave de `proposed_lwe` con `k_proof = 4`). La reproducen exactamente para Dilithium 2, 3 y 5.

## Qué problema se estima en cada candidato

Cada candidato se reduce a dos instancias: la de la **clave** (que la clave pública sea indistinguible de aleatoria) y la de la **solidez** (que nadie produzca una prueba aceptada sin conocer un testigo). `backend/benchmarking/hardness.py` construye ambas a partir de los parámetros efectivos que resuelve el propio protocolo.

### Clave

| Candidato | Relación | Instancia estimada |
|---|---|---|
| `proposed_lwe` | `t = A'·s + e mod q'`, `A' ∈ R_q'^{k'×k'}` | LWE de dimensión `n = k'·d = 1024`, `m = 1024` muestras, `q' = 8380417`, secreto y error `CBD(2)` |
| `standard_lwe` | `B = A·S + E mod q`, `S` con ℓ columnas | LWE `n = m = 1024`, `q = 8380417`, secreto y error `CBD(2)` |
| `binary_lwe` | igual, `S ∈ {0, 1}` | LWE `n = m = 1096`, secreto uniforme en `{0, 1}`, error `CBD(2)` |
| `lwr` | `B = ⌊(p/q)·A·S⌉` | LWE `n = m = 1016`, `q = 2^23`, secreto `CBD(2)`, error uniforme en `{−1, 0, 1, 2}` |
| `ring_lwe` | `b = a·s + e` en `Z_q[x]/(x^n + 1)` | LWE `n = m = 1024`, `q = 8380417`, secreto y error `CBD(2)` |

Decisiones de modelado, las mismas que usan los diseñadores de esos esquemas:

- **MLWE y Ring-LWE se estiman como LWE** de la misma dimensión. No se conoce un ataque que aproveche la estructura algebraica a estos tamaños; así lo hacen Kyber, Dilithium y Saber.
- **Las ℓ columnas de `S` comparten `A`.** Atacar una columna es una instancia LWE de dimensión `n`; tener ℓ de ellas no abarata el ataque de forma conocida.
- **LWR se estima como LWE con error uniforme** sobre el intervalo de redondeo, que para `q/p = 4` es `{−1, 0, 1, 2}` (el test `test_lwr_error_interval_matches_the_rounding_of_the_implementation` comprueba que el intervalo coincide con el redondeo del código). Es la heurística habitual para Saber; la reducción formal de LWR a LWE pierde mucho más.
- **El secreto binario** tiene media 1/2 y varianza 1/4. El estimador lo trata con el reescalado de Bai y Galbraith, que aprovecha que el secreto es más corto que el error. Por eso `binary_lwe` necesita una dimensión mayor.

### Solidez

Las pruebas son Fiat–Shamir con abortos. Un falsificador que gana sin conocer el secreto da una solución de SelfTargetSIS (Kiltz, Lyubashevsky y Schaffner, 2018): un vector corto `x` con `H(μ, M·x) = c`. Se estima como SIS en norma infinito, igual que Dilithium:

| Candidato | Matriz `M` | Filas × columnas | Cota de `‖x‖∞` |
|---|---|---|---|
| `proposed_lwe` | `[A' | I | t]` | 1024 × 2304 | `max(γ₁ − β, γ₂ + 1) = 131 026` |
| `standard_lwe` | `[A | I | B]` | `m × (n + m + ℓ)` = 1024 × 2176 | `γ − κ·η = 131 010` |
| `binary_lwe` | `[A | I | B]` | 1096 × 2320 | `γ − κ = 131 041` |
| `lwr` | `[A | I | B̃]` | 1016 × 2160 | `γ − κ·max(η, q/2p) = 131 010` |
| `ring_lwe` | `[a | 1 | b]` | 1024 × 3072 | `γ − κ·η = 131 040` |

La cota es la norma de una respuesta aceptada: lo que el verificador deja pasar. En los cinco la solidez queda al menos 34 bits por encima de la clave, así que no limita.

## Cómo se igualaron los parámetros

1. Se fijó la referencia: `proposed_lwe` con `k_proof = 4`, la elección de los autores, da 2^114.9 (bloque 393, dual híbrido).
2. `standard_lwe` y `ring_lwe` ya tenían la misma instancia de clave (dimensión 1024, `q = 8380417`, `CBD(2)`): no cambian.
3. `binary_lwe` con `n = m = 1024` daba 2^105.4. Se buscó la dimensión que da el mismo bloque: 1092 da 391, 1096 da 393 y 1100 da 395. Se eligió 1096.
4. `lwr` con `p = 2^20` daba 2^122.8, porque su error de redondeo (desviación ≈ 2.3) es mayor que el de los demás. Con `p = 2^21` el error queda en `{−1, …, 2}` y la cota del testigo en 2, igual que `η`: la prueba usa la misma `β` que `standard_lwe`. Con `n = 1024` daba 2^116.0; 1016 da 2^114.7, el más cercano.
5. Los parámetros de la prueba (`ℓ = 128`, `κ`, `γ = 2^17`) no cambian: la solidez queda por encima de la clave sin tocarlos.

El objetivo fue igualar la dureza estimada, no las dimensiones. Por eso `binary_lwe` y `lwr` no usan 1024: con la misma dimensión, uno sería más débil y otro más fuerte que el resto, y la comparación de tiempos y tamaños favorecería a uno.

## Tamaños y tiempos con estos parámetros

Corrida exploratoria de 30 autenticaciones por candidato (mediana), no evidencia de tesis. Tamaños en JSON canónico, lo que mide el runner.

| Candidato | `system_parameters` | Clave pública | Clave privada | Respuesta | Autenticación |
|---|---|---|---|---|---|
| `proposed_lwe` | 2 247 B | 3 936 B | 1 106 B | 4 681 B | 2.4 ms |
| `ring_lwe` | 6 002 B | 5 472 B | 2 818 B | 10 996 B | 2.1 ms |
| `standard_lwe` | 5.59 MB | 699 KB | 350 KB | 10 996 B | 11.3 ms |
| `lwr` | 5.51 MB | 694 KB | 347 KB | 10 908 B | 11.2 ms |
| `binary_lwe` | 6.41 MB | 748 KB | 211 KB | 11 764 B | 12.8 ms |

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

Con el estimador montado en `/estimator`, `tests/test_hardness.py` además comprueba que se reproducen Kyber512 y Dilithium2 y que los cinco candidatos quedan a menos de un bit de `proposed_lwe`. Sin él, esos tests se saltan.

Si se cambia un parámetro en `default.json`, el cálculo usa el nuevo valor automáticamente: `hardness_cli` resuelve los parámetros con el propio protocolo.

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
