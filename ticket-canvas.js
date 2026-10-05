const crypto = require('crypto');

const SECRET_KEY = 'demo_event_secret_key';

// Function to generate a secure digital signature for a ticket
function generateTicketPayload(ticketId, userId) {
  const payload = JSON.stringify({
    ticketId: ticketId,
    userId: userId,
    issuedAt: Date.now()
  });

  // Create HMAC signature
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex');

  return {
    payload: payload,
    signature: signature
  };
}

// Example usage
const secureTicket = generateTicketPayload('TICK-99482', 'Liam');
console.log('Signed Ticket Data:', secureTicket);
