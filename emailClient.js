require('dotenv').config({ quiet: true });
const { Resend } = require('resend');

// Resend's shared sandbox sender (onboarding@resend.dev) needs no setup but can only
// deliver to the email address the Resend account itself was created with - real
// delivery to arbitrary user addresses needs a verified sending domain in the Resend
// dashboard, at which point RESEND_FROM_ADDRESS should be set to something like
// "Fenn <no-reply@fennapp.com>".
const FROM_ADDRESS = process.env.RESEND_FROM_ADDRESS || 'Fenn <onboarding@resend.dev>';

// Constructed lazily, not at module load - the Resend constructor throws immediately if
// RESEND_API_KEY is missing, and this module is required from auth.js, which index.js
// requires at startup. Constructing eagerly would crash the entire server on boot the
// moment this deploys, before the key's even been added to Railway - not just break
// password reset emails specifically. Deferring construction to the moment an email
// actually needs sending means a missing key only ever surfaces there, where
// requestPasswordReset (auth.js) already catches and logs it without failing the request.
let resend = null;
function getResendClient() {
  if (!resend) resend = new Resend(process.env.RESEND_API_KEY);
  return resend;
}

async function sendPasswordResetEmail(toEmail, code) {
  await getResendClient().emails.send({
    from: FROM_ADDRESS,
    to: toEmail,
    subject: 'Your Fenn password reset code',
    text: `Your password reset code is ${code}. It expires in 15 minutes.\n\nIf you didn't request this, you can safely ignore this email.`,
    html: `<p>Your password reset code is <strong>${code}</strong>.</p><p>It expires in 15 minutes.</p><p>If you didn't request this, you can safely ignore this email.</p>`,
  });
}

module.exports = { sendPasswordResetEmail };
