// Mirrors app/legalContent.js exactly (same wording shown in-app before signup) - kept as
// a separate copy here since the app and backend are separate deployable projects, but this
// is the version that gets hosted publicly so Plaid (and anyone else) can review it without
// installing the app. Keep both files in sync if the policy content changes.

const PRIVACY_POLICY = {
  title: 'Privacy Policy',
  sections: [
    {
      heading: 'Information we collect',
      body: 'Your email address, and a password (stored as a secure one-way hash, never in plain text) if you sign up that way, or your Apple ID identifier if you use Sign in with Apple. If you connect a bank account, transaction and balance data provided to us by Plaid, our bank-connection partner. Budget and expense information you enter yourself.',
    },
    {
      heading: 'How we use it',
      body: "To operate Fenn - calculating your spending, budgets, and streaks, and detecting recurring bills. To send you notifications you've turned on, which are generated and delivered entirely on your own device, not through our servers. To respond if you contact support.",
    },
    {
      heading: 'How we share it',
      body: "With Plaid, Inc., to connect to and retrieve data from your bank on your behalf. With Neon and Railway, our database and server hosting providers, who store data on our behalf under their own security commitments. We do not sell your data, and we do not share it with advertisers.",
    },
    {
      heading: 'Security',
      body: 'Bank access credentials are encrypted at rest. Passwords are hashed, never stored in plain text. All data in transit is encrypted (HTTPS).',
    },
    {
      heading: 'Your choices',
      body: 'You can disconnect a bank account at any time from Settings. You can delete your account at any time from Settings, which permanently and immediately deletes your budget, expenses, and bank connections. You can control which notifications you receive from Settings.',
    },
    {
      heading: "Children's privacy",
      body: 'Fenn is not directed at children under 13, and we do not knowingly collect information from them.',
    },
    {
      heading: 'Changes to this policy',
      body: 'We may update this policy from time to time. Continuing to use Fenn after a change means you accept the update.',
    },
    {
      heading: 'Contact',
      body: 'Questions about this policy can be sent to jordan.cutter@yahoo.com.',
    },
  ],
};

const TERMS_OF_SERVICE = {
  title: 'Terms of Service',
  sections: [
    {
      heading: 'Acceptance of terms',
      body: 'By creating a Fenn account, you agree to these terms.',
    },
    {
      heading: 'Description of service',
      body: 'Fenn helps you track day-to-day discretionary spending against a budget you set. It is not a comprehensive budgeting, investment, tax, or financial advisory tool, and nothing in Fenn should be taken as financial advice.',
    },
    {
      heading: 'Your account',
      body: "You're responsible for keeping your login credentials secure and for all activity that happens under your account.",
    },
    {
      heading: 'Bank connections',
      body: "Connecting a bank account is optional and requires a paid subscription. Data is retrieved through Plaid, and Fenn's accuracy depends on the completeness and accuracy of the data Plaid provides.",
    },
    {
      heading: 'Subscriptions',
      body: 'Some features require a paid subscription. Pricing, billing cycle, and cancellation terms are presented at the time of purchase.',
    },
    {
      heading: 'Acceptable use',
      body: "Don't misuse the service, attempt to access other users' data, or use Fenn for any unlawful purpose.",
    },
    {
      heading: 'Disclaimer of warranties',
      body: 'Fenn is provided "as is" without warranties of any kind, express or implied.',
    },
    {
      heading: 'Limitation of liability',
      body: 'To the maximum extent permitted by law, Fenn is not liable for indirect, incidental, or consequential damages arising from your use of the service.',
    },
    {
      heading: 'Termination',
      body: 'You may stop using Fenn and delete your account at any time. We may suspend or terminate accounts that violate these terms.',
    },
    {
      heading: 'Changes to these terms',
      body: 'We may update these terms from time to time. Continuing to use Fenn after a change means you accept the update.',
    },
    {
      heading: 'Contact',
      body: 'Questions about these terms can be sent to jordan.cutter@yahoo.com.',
    },
  ],
};

module.exports = { PRIVACY_POLICY, TERMS_OF_SERVICE };
