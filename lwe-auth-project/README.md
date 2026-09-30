# LWE Authentication Prototype

Backend experimental para comparar mecanismos de autenticación tradicionales con construcciones basadas en LWE.

## Estado actual

- `standard` (ECDSA P-256): flujo challenge/response funcional y expuesto por la API.
- `lwe` / `standard_lwe`: el material de claves Standard-LWE se conserva como primitiva en `crypto_core/lwe/keygen.py`, pero todavía no existe un protocolo de autenticación verificable y **no se expone como método utilizable**.
- `binary_lwe`: la generación con secreto binario también se conserva como primitiva, sin anunciarla como protocolo hasta que exista un challenge/response correcto.
- Los archivos vacíos reservados para protocolos futuros se eliminaron. Se deben crear cuando exista una implementación real.

La API falla de forma explícita con HTTP 501 si se intenta usar un protocolo LWE todavía no implementado, en lugar de aceptar respuestas sin verificarlas.

## Ejecutar con Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

La API queda disponible en `http://localhost:8010` por defecto y expone:

- `GET /health`
- `GET /api/v1/methods`
- `POST /api/v1/generate_keys`
- `POST /api/v1/challenge`
- `POST /api/v1/solve`
- `POST /api/v1/verify`

PostgreSQL se publica por defecto en el puerto `5437` del host y escucha en `5432` dentro del contenedor. El esquema SQL se conserva como infraestructura preparada para la posterior integración de persistencia; el backend actual todavía no consume la base de datos.

## Pruebas

Desde `backend/`:

```bash
python -m unittest discover -s tests -v
```

Las pruebas actuales cubren el flujo ECDSA, manipulación de desafíos y resolución del registro de protocolos. Las implementaciones LWE quedan fuera de la API hasta definir correctamente su protocolo de autenticación.
