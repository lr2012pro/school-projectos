const crypto = require('crypto');

// Bewaar dit geheim veilig op de server (bijv. via proces.env.SECRET_KEY)
const SECRET_KEY = process.env.SECRET_KEY || 'demoticket_secret_key_2026';

/**
 * Genereert een cryptografisch ondertekend ticket-payload voor de QR-code.
 * @param {string} ticketId - Uniek id van het ticket.
 * @param {string} userId - Uniek id van de koper.
 * @returns {object} Payload inclusief HMAC-handtekening.
 */
function createSignedTicketPayload(ticketId, userId) {
  const timestamp = Math.floor(Date.now() / 1000);

  const payload = {
    ticketId: ticketId,
    userId: userId,
    event: 'Tomorrowland Demo',
    timestamp: timestamp
  };

  // Maak een consistente string om te ondertekenen
  const dataToSign = `${payload.ticketId}:${payload.userId}:${payload.timestamp}`;

  // Genereer HMAC-SHA256 handtekening
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(dataToSign)
    .digest('hex');

  return {
    ...payload,
    signature: signature
  };
}

/**
 * Verifieert of een gescand ticket authentiek en ongewijzigd is.
 * @param {object} scannedData - De ontvangen JSON-data uit de QR-code.
 * @returns {boolean} True als de handtekening klopt.
 */
function verifyTicketPayload(scannedData) {
  const { ticketId, userId, timestamp, signature } = scannedData;

  if (!ticketId || !userId || !timestamp || !signature) {
    return false;
  }

  const dataToSign = `${ticketId}:${userId}:${timestamp}`;
  const expectedSignature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(dataToSign)
    .digest('hex');

  // Gebruik timingSafeEqual om timing attacks te voorkomen
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

module.exports = {
  createSignedTicketPayload,
  verifyTicketPayload
};
