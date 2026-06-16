// api/trustpilot-payload.js  (Vercel Serverless Function — Node runtime)
//
// Cifra i dati cliente per il Review Collector in-app di Trustpilot.
// La chiave segreta vive SOLO qui (variabile d'ambiente), mai nel frontend.

const { createCipheriv, createHash, createHmac, randomBytes } = require('crypto');

function createPayload({ secret, customerData }) {
  const iv = randomBytes(12);
  const jsonData = JSON.stringify(customerData);
  const key = createHash('sha256').update(secret).digest();

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(jsonData, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const tag = cipher.getAuthTag().toString('base64');
  const ivBase64 = iv.toString('base64');

  const signatureData = secret + customerData.email + customerData.reference;
  const signature = createHmac('sha256', secret).update(signatureData).digest('hex');

  return { data: encrypted, iv: ivBase64, tag, sig: signature };
}

// Domini autorizzati a chiamare questo endpoint
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());

module.exports = async (req, res) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { name, email, reference } = req.body || {};
    if (!name || !email || !reference) {
      return res.status(400).json({ error: 'Missing name, email or reference' });
    }

    const secret = process.env.TRUSTPILOT_SECRET; // chiave segreta Trustpilot
    if (!secret) return res.status(500).json({ error: 'Server not configured' });

    const payload = createPayload({ secret, customerData: { name, email, reference } });

    // Esponiamo anche il BUID al frontend (non è segreto)
    return res.status(200).json({
      buid: process.env.TRUSTPILOT_BUID,
      ...payload,
    });
  } catch (err) {
    console.error('Trustpilot payload error:', err);
    return res.status(500).json({ error: 'Encryption failed' });
  }
};
