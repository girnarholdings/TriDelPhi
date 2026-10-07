export default function Checkout() {
  return (
    <section>
      <p>$15 per month</p>
      <button
        onClick={() =>
          fetch("/api/checkout", {
            method: "POST",
            body: JSON.stringify({ mode: "subscription" }),
          })
        }
      >
        Subscribe
      </button>
    </section>
  );
}
