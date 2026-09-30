-- Habilitar extensión para UUIDs (útil para identificadores de desafío difíciles de predecir)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tabla de Usuarios
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de Claves Públicas
-- Usamos JSONB para "key_data" porque ECDSA guarda un string (PEM), 
-- pero LWE guarda arreglos multidimensionales (Matriz A, Vector b, q).
CREATE TABLE IF NOT EXISTS public_keys (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    protocol_name VARCHAR(30) NOT NULL, -- ej: 'standard_ecdsa', 'standard_lwe', 'binary_lwe'
    key_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de Desafíos de Autenticación
-- Registra el desafío generado por el servidor a la espera de la respuesta matemática del cliente.
CREATE TABLE IF NOT EXISTS auth_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    protocol_name VARCHAR(30) NOT NULL,
    challenge_data JSONB NOT NULL,        -- Guarda el vector 'r' (LWE) o 'nonce' (ECDSA)
    status VARCHAR(20) DEFAULT 'PENDING', -- Estados: 'PENDING', 'SUCCESS', 'FAILED'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);