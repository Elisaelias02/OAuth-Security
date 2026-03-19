// lab_oauth.js
// Ejercicio: construir un servidor de recursos que valide access tokens
// y un cliente que use Client Credentials para obtener uno.

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// PARTE A: El "Authorization Server" simplificado
// (en producción usarías Auth0, Keycloak, etc.)
const authServer = express();
authServer.use(express.json());

const REGISTERED_CLIENTS = {
  'service-client-id': {
    secret: 'service-client-secret',
    allowedScopes: ['data:read', 'data:write']
  }
};

const JWT_SECRET = crypto.randomBytes(32).toString('hex');

authServer.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret, scope } = req.body;

  // TODO 1: Verificar que grant_type sea 'client_credentials'
  // Si no lo es, retornar error 400 con { error: 'unsupported_grant_type' }


  // TODO 2: Verificar que client_id existe en REGISTERED_CLIENTS
  // y que client_secret coincide
  // Si no, retornar error 401 con { error: 'invalid_client' }


  // TODO 3: Verificar que los scopes solicitados están en allowedScopes del cliente
  const requestedScopes = scope ? scope.split(' ') : [];
  // Si algún scope no está permitido, retornar error 400 con { error: 'invalid_scope' }


  // TODO 4: Emitir el JWT access token con:
  // - sub: client_id
  // - scope: scope (el solicitado)
  // - iss: 'http://localhost:4000'
  // - aud: 'http://localhost:3000'
  // - exp: 1 hora desde ahora (usar expiresIn: '1h' en jwt.sign)
  const accessToken = null; // Reemplazar con jwt.sign(...)

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: scope
  });
});

authServer.listen(4000, () => console.log('Auth Server en puerto 4000'));

// ============================================================
// PARTE B: El Resource Server
// ============================================================
const resourceServer = express();
resourceServer.use(express.json());

function requireScope(requiredScope) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;

    // TODO 5: Extraer el Bearer token del header Authorization
    // Formato: "Bearer <token>"
    // Si no hay header o no empieza con 'Bearer ', retornar 401
    const token = null; // Reemplazar


    // TODO 6: Verificar el JWT con jwt.verify()
    // - secret: JWT_SECRET
    // - audience: 'http://localhost:3000'
    // - issuer: 'http://localhost:4000'
    // Si falla, retornar 401 con { error: 'invalid_token' }
    let payload;
    try {
      payload = null; // Reemplazar con jwt.verify(...)
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', detail: err.message });
    }

    // TODO 7: Verificar que payload.scope incluye el requiredScope
    // Si no, retornar 403 con { error: 'insufficient_scope' }


    req.tokenPayload = payload;
    next();
  };
}

resourceServer.get('/api/data',
  requireScope('data:read'),  // Este endpoint requiere data:read
  (req, res) => {
    res.json({
      message: '¡Acceso autorizado!',
      clientId: req.tokenPayload.sub,
      scope: req.tokenPayload.scope
    });
  }
);

resourceServer.listen(3000, () => console.log('Resource Server en puerto 3000'));

// PARTE C: El Client — obtener token y usarlo
const axios = require('axios');

async function runClient() {
  console.log('\n--- Iniciando flujo Client Credentials ---');

  // TODO 8: Hacer POST a http://localhost:4000/oauth/token con:
  // { grant_type, client_id, client_secret, scope }
  // Guardar el access_token de la respuesta
  const tokenResponse = null; // Reemplazar con axios.post(...)
  const accessToken = tokenResponse?.data?.access_token;

  if (!accessToken) {
    console.error('No se obtuvo access token');
    return;
  }

  console.log('✓ Access token obtenido');

  // TODO 9: Hacer GET a http://localhost:3000/api/data
  // con el header Authorization: Bearer <accessToken>
  // Imprimir la respuesta
  const dataResponse = null; // Reemplazar con axios.get(...)
  console.log('✓ Respuesta de la API:', dataResponse?.data);
}

// Esperar a que los servidores arranquen, luego correr el cliente
setTimeout(runClient, 1000);
