import { planById } from "./plans.ts";
import type { TrustStore } from "./store.ts";
import { parseEvent } from "./stripe.ts";

/** Apply a verified Stripe event to an account. Returns a short audit note. */
export async function handleStripeEvent(
  _env: unknown,
  store: TrustStore,
  event: ReturnType<typeof parseEvent>,
): Promise<string> {
  if (!event) return "ignored: unparsable";
  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Record<string, unknown>;
    const metadata = (session.metadata ?? {}) as Record<string, unknown>;
    const accountId = String(session.client_reference_id ?? metadata.account_id ?? "");
    const plan = planById(String(metadata.plan ?? ""));
    if (!accountId || !plan) return "ignored: missing account or plan";
    await store.ensureAccount(accountId, null, 0);
    await store.addCredits(accountId, plan.credits);
    if (plan.mode === "subscription") {
      await store.setPlan(accountId, plan.id, typeof session.customer === "string" ? session.customer : null);
    }
    return `credited ${plan.credits} (${plan.id})`;
  }
  if (event.type === "invoice.paid") {
    const invoice = event.data.object as Record<string, unknown>;
    // The first invoice also fires checkout.session.completed; only renewals
    // are credited here to avoid double-crediting the first month.
    if (invoice.billing_reason !== "subscription_cycle") return "ignored: not a renewal";
    const customer = typeof invoice.customer === "string" ? invoice.customer : "";
    if (!customer) return "ignored: no customer";
    const account = await store.findAccountByCustomer(customer);
    if (!account) return "ignored: unknown customer";
    const plan = planById(account.plan);
    if (!plan || plan.mode !== "subscription") return "ignored: no subscription plan";
    await store.addCredits(account.id, plan.credits);
    return `renewal credited ${plan.credits} (${plan.id})`;
  }
  return "ignored";
}