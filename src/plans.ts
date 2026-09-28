/**
 * Trust plans. Amounts in cents; credits are added per successful payment (and
 * per subscription renewal). One profile/terms lookup = one credit.
 */
export interface Plan {
  id: "pack25" | "pro" | "b2b";
  label: string;
  description: string;
  amountCents: number;
  credits: number;
  mode: "payment" | "subscription";
  priceEnv?: "STRIPE_PRICE_PACK" | "STRIPE_PRICE_PRO" | "STRIPE_PRICE_B2B";
}

export const PLANS: Plan[] = [
  {
    id: "pack25",
    label: "Trust credits — 25",
    description: "25 profile/terms lookups, no expiry.",
    amountCents: 500,
    credits: 25,
    mode: "payment",
    priceEnv: "STRIPE_PRICE_PACK",
  },
  {
    id: "pro",
    label: "Trust Pro — 200/month",
    description: "200 lookups per month, priority.",
    amountCents: 900,
    credits: 200,
    mode: "subscription",
    priceEnv: "STRIPE_PRICE_PRO",
  },
  {
    id: "b2b",
    label: "Trust API — 2,000/month",
    description: "2,000 lookups per month, API keys, webhooks, priority support.",
    amountCents: 7900,
    credits: 2000,
    mode: "subscription",
    priceEnv: "STRIPE_PRICE_B2B",
  },
];

export function planById(id: string): Plan | null {
  return PLANS.find((p) => p.id === id) ?? null;
}