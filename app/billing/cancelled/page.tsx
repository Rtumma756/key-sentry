// Checkout cancelled landing page.
//
// Stripe redirects here when the buyer abandons Checkout
// (cancel_url in lib/billing.ts). No charge was made and the
// workspace stays on its current plan.

export default function BillingCancelledPage() {
  return (
    <div className="app">
      <p style={{ margin: "0 0 1rem 0" }}>
        <a href="/app">← Back to scanner</a>
      </p>
      <h1 style={{ margin: "0 0 0.5rem 0" }}>Checkout cancelled</h1>
      <p style={{ margin: "0 0 0.5rem 0" }}>
        No charge was made — you&apos;re still on your current plan.
      </p>
      <p style={{ margin: 0 }}>
        <a href="/pricing">Back to plans &amp; pricing</a>
      </p>
    </div>
  );
}
