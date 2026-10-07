"use client";

export default function PricingPage() {
  return (
    <section>
      <h1>Pro</h1>
      <p>$20 per month</p>
      <button
        onClick={() =>
          stripe.redirectToCheckout({ mode: "subscription", lineItems: [{ price: "price_pro", quantity: 1 }] })
        }
      >
        Subscribe
      </button>
    </section>
  );
}
