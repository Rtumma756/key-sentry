// Potential-savings estimation for KeySentry scan findings.
//
// TypeScript port of the CLI scanner's savings.py — SAME pricing table,
// SAME model, SAME numbers. Keep the two in sync: if a price or scenario
// changes in one, change it in the other.
//
// Estimates the money NOT spent because leaked API keys were found before
// they could be abused. This is an ESTIMATE, not a verified loss: no key
// is ever tested against a provider, so billing status (free tier vs paid)
// and whether a key is still live are unknown.
//
// Model (see aiscan results/DISCOVERY_INTELLIGENCE.md, 2026-11-19):
//   savings(provider) = keys x P(abuse) x daily_cost x window_days
//   daily_cost = throughput_tokens_per_day x blended_rate
//                (+ Perplexity request fees: 5,000 req/day x $8.00/1,000)
//   blended_rate = (3 x input + output) / 4   (3:1 input:output token mix)
//   OpenRouter blended rate x 1.055 (its 5.5% credit fee)
//   "Unknown (generic)" and any provider without a researched price use
//   the mean blended rate of the researched providers ($3.1247/1M tokens).
//
// Scenarios:
//   conservative: 10% of keys abused,  5M tokens/day,  7 days undetected
//   expected:     25% of keys abused, 25M tokens/day, 30 days undetected
//   worst-case:   50% of keys abused, 100M tokens/day, 30 days undetected
//
// Pricing sources (list prices, Nov 2026 — re-check before quoting):
//   OpenAI GPT-5 $1.25/$10, Anthropic Sonnet 5.5 $2/$10, Gemini 2.5 Pro
//   $1.25/$10, OpenRouter pass-through + 5.5%, Groq GPT-OSS 120B
//   $0.15/$0.60, Perplexity Sonar Pro $3/$15 + $6-$14/1k requests,
//   Hugging Face Llama 3.3 70B $0.59/$0.79, xAI Grok 4.7 $2/$6.
//   Full citations: aiscan results/DISCOVERY_INTELLIGENCE.md §2.
//
// Client-side only: pure arithmetic on finding counts. No network calls,
// no real keys anywhere — findings carry masked values only.

import type { Finding } from "./scan";

export const SAVINGS_MODEL_VERSION = "aiscan-savings-v1";

export const SAVINGS_DISCLAIMER =
  "Estimate based on public pricing and documented abuse costs — not a verified loss. " +
  "No key was tested against any provider; billing status (free tier vs paid) is unknown, " +
  "and free-tier keys would cost far less.";

export const SAVINGS_METHODOLOGY_NOTE =
  "Estimate based on public pricing and documented abuse costs — not a verified loss.";

// Confidence split (2026-11-19): "real-looking" only proves a key matches
// a documented format and sits in real code/config context — it does NOT
// prove the key is live or has paid billing, because no found key is ever
// tested against a provider. So every estimate is reported twice:
// "Potential (candidate) savings" (all findings, unconfirmed) and
// "Owner-verified savings" (same model, only keys the owner confirmed
// live and theirs). Until any key is verified the verified side is $0.
export const OWNER_VERIFIED_NOTE =
  "Owner-verified savings count only keys the owner confirmed live and " +
  "theirs, then marked verified. Unconfirmed candidates never count here.";

export const VERIFIED_NOT_AVAILABLE_NOTE =
  "Not yet available — the vault isn't deployed yet. Once it is, keys the " +
  "owner stores in the vault (after confirming they are live and theirs) " +
  "count here as owner-verified savings. Until then this side stays $0; " +
  "the candidate figures above are unconfirmed estimates, not verified losses.";

interface ProviderPricing {
  model: string;
  inputPer1m: number;
  outputPer1m: number;
  feePer1kRequests: number;
  feeMultiplier?: number;
}

// $ per 1M tokens for the flagship model used in the report.
export const PROVIDER_PRICING: Record<string, ProviderPricing> = {
  OpenAI: {
    model: "GPT-5",
    inputPer1m: 1.25,
    outputPer1m: 10.0,
    feePer1kRequests: 0,
  },
  Anthropic: {
    model: "Claude Sonnet 5.5",
    inputPer1m: 2.0,
    outputPer1m: 10.0,
    feePer1kRequests: 0,
  },
  "Google Gemini": {
    model: "Gemini 2.5 Pro",
    inputPer1m: 1.25,
    outputPer1m: 10.0,
    feePer1kRequests: 0,
  },
  OpenRouter: {
    model: "Claude Sonnet 5.5 via OpenRouter",
    inputPer1m: 2.0,
    outputPer1m: 10.0,
    feePer1kRequests: 0,
    feeMultiplier: 1.055,
  },
  Groq: {
    model: "GPT-OSS 120B",
    inputPer1m: 0.15,
    outputPer1m: 0.6,
    feePer1kRequests: 0,
  },
  Perplexity: {
    model: "Sonar Pro",
    inputPer1m: 3.0,
    outputPer1m: 15.0,
    feePer1kRequests: 8.0,
  },
  "Hugging Face": {
    model: "Llama 3.3 70B (Inference Providers)",
    inputPer1m: 0.59,
    outputPer1m: 0.79,
    feePer1kRequests: 0,
  },
  xAI: {
    model: "Grok 4.7",
    inputPer1m: 2.0,
    outputPer1m: 6.0,
    feePer1kRequests: 0,
  },
};

// Providers the scanner detects but the report did not price-research
// (DeepSeek, Mistral, Cohere, Together AI, Replicate) use this generic
// rate until researched — same as the report's "Unknown" handling.
export const GENERIC_BLENDED_PER_1M = 3.1247; // mean of researched blended rates

export interface ScenarioSpec {
  pAbuse: number;
  throughputTokensPerDay: number;
  windowDays: number;
}

export const SCENARIOS: Record<"conservative" | "expected" | "worstCase", ScenarioSpec> = {
  conservative: { pAbuse: 0.1, throughputTokensPerDay: 5_000_000, windowDays: 7 },
  expected: { pAbuse: 0.25, throughputTokensPerDay: 25_000_000, windowDays: 30 },
  worstCase: { pAbuse: 0.5, throughputTokensPerDay: 100_000_000, windowDays: 30 },
};

// Assumed incident-response cost per abused key (assumption, not sourced):
// a few hours of engineering + security time to investigate, rotate,
// audit usage and dispute charges. Shown separately from usage bills.
export const INCIDENT_RESPONSE_PER_KEY_USD = 2500;

export const PERPLEXITY_REQUESTS_PER_DAY = 5000;

export function blendedRatePer1m(provider: string): number {
  const spec = PROVIDER_PRICING[provider];
  if (!spec) return GENERIC_BLENDED_PER_1M;
  const rate = (3 * spec.inputPer1m + spec.outputPer1m) / 4;
  return rate * (spec.feeMultiplier ?? 1);
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function perKeyDailyCost(provider: string, throughputTokensPerDay: number): number {
  let cost =
    (throughputTokensPerDay / 1_000_000) * blendedRatePer1m(provider);
  const spec = PROVIDER_PRICING[provider];
  if (spec && spec.feePer1kRequests) {
    cost += (PERPLEXITY_REQUESTS_PER_DAY / 1000) * spec.feePer1kRequests;
  }
  return cost;
}

export interface ScenarioEstimate {
  pAbuse: number;
  throughputTokensPerDay: number;
  windowDays: number;
  usageBillSavingsUsd: number;
  perKeyUsd: number;
  expectedAbusedKeys: number;
  incidentResponseSavingsUsd: number;
  byProviderUsd: Record<string, number>;
}

export interface SavingsEstimate {
  model: string;
  disclaimer: string;
  totalKeys: number;
  byProvider: Record<string, number>;
  scenarios: Record<"conservative" | "expected" | "worstCase", ScenarioEstimate>;
  headlineRangeUsd: Record<"conservative" | "expected" | "worstCase", number>;
  /** Keys the owner confirmed live (via the vault, once it is deployed). */
  verifiedKeys: number;
  /** Same model, verified findings only. All $0 until any key is verified. */
  ownerVerified: {
    totalKeys: number;
    byProvider: Record<string, number>;
    scenarios: Record<"conservative" | "expected" | "worstCase", ScenarioEstimate>;
    headlineRangeUsd: Record<"conservative" | "expected" | "worstCase", number>;
  };
  ownerVerifiedNote: string;
}

type ScenarioMap = Record<
  "conservative" | "expected" | "worstCase",
  ScenarioEstimate
>;

/** The model run over one list of findings (candidate or verified). */
function estimateFor(findings: Finding[]): {
  totalKeys: number;
  byProvider: Record<string, number>;
  scenarios: ScenarioMap;
  headlineRangeUsd: Record<"conservative" | "expected" | "worstCase", number>;
} {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.provider] = (counts[f.provider] ?? 0) + 1;
  }
  const totalKeys = findings.length;

  const scenarios = {} as ScenarioMap;
  (Object.keys(SCENARIOS) as Array<keyof typeof SCENARIOS>).forEach((name) => {
    const spec = SCENARIOS[name];
    const byProviderUsd: Record<string, number> = {};
    for (const provider of Object.keys(counts).sort()) {
      byProviderUsd[provider] = round2(
        counts[provider] *
          spec.pAbuse *
          perKeyDailyCost(provider, spec.throughputTokensPerDay) *
          spec.windowDays,
      );
    }
    const total = round2(
      Object.values(byProviderUsd).reduce((a, b) => a + b, 0),
    );
    scenarios[name] = {
      pAbuse: spec.pAbuse,
      throughputTokensPerDay: spec.throughputTokensPerDay,
      windowDays: spec.windowDays,
      usageBillSavingsUsd: total,
      perKeyUsd: totalKeys ? round2(total / totalKeys) : 0,
      expectedAbusedKeys: round2(totalKeys * spec.pAbuse),
      incidentResponseSavingsUsd: round2(
        totalKeys * spec.pAbuse * INCIDENT_RESPONSE_PER_KEY_USD,
      ),
      byProviderUsd,
    };
  });

  return {
    totalKeys,
    byProvider: counts,
    scenarios,
    headlineRangeUsd: {
      conservative: scenarios.conservative.usageBillSavingsUsd,
      expected: scenarios.expected.usageBillSavingsUsd,
      worstCase: scenarios.worstCase.usageBillSavingsUsd,
    },
  };
}

/**
 * Per-provider + total savings ranges for a list of findings, split in two.
 *
 * The top-level fields are the CANDIDATE estimate (all findings) — the
 * same numbers as before this split. `ownerVerified` is the same model
 * run over `verifiedFindings` only: keys the owner confirmed live and
 * theirs (via the vault, once it is deployed). With no verified findings
 * the owner-verified side is all $0.
 */
export function estimateSavings(
  findings: Finding[],
  verifiedFindings: Finding[] = [],
): SavingsEstimate {
  const candidate = estimateFor(findings);
  return {
    model: SAVINGS_MODEL_VERSION,
    disclaimer: SAVINGS_DISCLAIMER,
    ...candidate,
    verifiedKeys: verifiedFindings.length,
    ownerVerified: estimateFor(verifiedFindings),
    ownerVerifiedNote: OWNER_VERIFIED_NOTE,
  };
}

export function formatUsd(n: number): string {
  return `$${n.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
