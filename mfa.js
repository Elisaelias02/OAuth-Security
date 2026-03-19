// npm install speakeasy qrcode

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// PASO 1: Registro del MFA (al activarlo el usuario)
async function setupMFA(userId, userEmail) {
  // Generar secret único para este usuario
  const secret = speakeasy.generateSecret({
    name: `MiApp (${userEmail})`,   // Nombre que aparece en el autenticador
    issuer: 'MiApp'
  });

  // Generar QR code para escanear
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  // Guardar el secret en la base de datos (PENDIENTE de confirmar)
  // No activar MFA hasta que el usuario confirme con un código válido
  await db.users.update(userId, {
    mfaSecret: secret.base32,     // Guardar en base32
    mfaPending: true,             // No activo aún
    mfaEnabled: false
  });

  // Retornar QR y clave manual (para mostrar UNA SOLA VEZ)
  return {
    qrCode: qrCodeUrl,
    manualKey: secret.base32
  };
}

// PASO 2: Confirmar que el usuario configuró correctamente
async function confirmMFA(userId, totpCode) {
  const user = await db.users.findById(userId);

  if (!user.mfaPending) {
    return { success: false, error: 'MFA setup not started' };
  }

  const isValid = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: totpCode,
    window: 1    // Tolerancia de ±1 intervalo (30s antes o después)
  });

  if (!isValid) {
    return { success: false, error: 'Invalid code — try again' };
  }

  // Activar MFA
  await db.users.update(userId, {
    mfaPending: false,
    mfaEnabled: true
  });

  // Generar códigos de respaldo (para cuando el usuario pierde su teléfono)
  const backupCodes = Array.from({ length: 8 }, () =>
    require('crypto').randomBytes(5).toString('hex').toUpperCase()
  );

  // Guardar códigos hasheados (nunca en texto plano)
  const bcrypt = require('bcrypt');
  const hashedCodes = await Promise.all(
    backupCodes.map(code => bcrypt.hash(code, 10))
  );

  await db.users.update(userId, { backupCodes: hashedCodes });

  return {
    success: true,
    backupCodes  // Mostrar UNA SOLA VEZ — el usuario debe guardarlos
  };
}

// PASO 3: Verificar MFA en cada login
async function verifyMFA(userId, totpCode) {
  const user = await db.users.findById(userId);

  if (!user.mfaEnabled) {
    return { success: true };  // MFA no activado — continuar
  }

  // Verificar código TOTP
  const isValid = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: totpCode,
    window: 1
  });

  if (isValid) {
    return { success: true };
  }

  // Si el TOTP falla, verificar si es un código de respaldo
  if (user.backupCodes && user.backupCodes.length > 0) {
    const bcrypt = require('bcrypt');
    for (let i = 0; i < user.backupCodes.length; i++) {
      const matches = await bcrypt.compare(totpCode, user.backupCodes[i]);
      if (matches) {
        // Código de respaldo usado → eliminarlo (son de un solo uso)
        const remainingCodes = user.backupCodes.filter((_, idx) => idx !== i);
        await db.users.update(userId, { backupCodes: remainingCodes });

        console.log(` Usuario ${userId} usó código de respaldo`);
        return { success: true, usedBackupCode: true };
      }
    }
  }

  return { success: false, error: 'Invalid MFA code' };
}

// PASO 4: Integrar en el flujo de login
app.post('/login', async (req, res) => {
  const { email, password, mfaCode } = req.body;

  // 1. Verificar email + password
  const user = await verifyCredentials(email, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // 2. Si el usuario tiene MFA activado, verificar el código
  if (user.mfaEnabled) {
    if (!mfaCode) {
      // Primera fase: credenciales ok, pedir MFA
      return res.status(200).json({
        requiresMFA: true,
        message: 'Enter your authenticator code'
      });
    }

    const mfaResult = await verifyMFA(user.id, mfaCode);
    if (!mfaResult.success) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
  }

  // 3. Login completo — emitir sesión
  const sessionToken = require('crypto').randomBytes(32).toString('hex');
  await db.sessions.create({
    token: sessionToken,
    userId: user.id,
    expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000)  // 8 horas
  });

  res.cookie('session', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });

  res.json({ success: true, redirectTo: '/dashboard' });
});
