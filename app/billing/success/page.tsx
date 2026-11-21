// Checkout success landing page.
//
// Stripe redirects here after a completed Checkout Session
// (success_url in lib/billing.ts). The plan itself is applied by the
// Stripe webhook (POST /api/billing/webhook) — this page never sets
// a plan directly, it just tells the user what happens next.

export default function BillingSuccessPage() {
  return (
    <div className="app">
      <p style={{ margin: "0 0 1rem 0" }}>
        <a href="/">← Back to dashboard</a>
      </p>
      <h1 style={{ margin: "0 0 0.5rem 0" }}>Payment received — thanks!</h1>
      <p style={{ margin: "0 0 0.5rem 0" }}>
        Your new plan activates once Stripe confirms the payment — usually
        within seconds. If the dashboard still shows your old plan, refresh
        it in a moment.
      </p>
      <p style={{ margin: 0 }}>
        <a href="/pricing">View plans</a>
      </p>
    </div>
  );
}
