/**
 * Storage for EntangleIT Trust. One interface, two implementations: D1 in the
 * Worker (shared `entangleit` database, tr_ tables) and an in-memory map in
 * tests. Only counters, refs, bindings, and signed profiles are stored —
 * never request content.
 */

// ---------- rows ----------

export interface Account {
  id: string;
  email: string | null;
  credits: number;
  plan: string;
  stripe_customer: string | null;
  created_at: number;
}

export interface Observation {
  id: string;
  subject: string;
  source: string;
  kind: string;
  ref: string;
  value: number | null;
  meta_json: string;
  observed_at: number;
}

export interface ObservationInput {
  subject: string;
  source: string;
  kind: string;
  ref: string;
  value?: number | null;
  meta?: Record<string, unknown>;
  observed_at?: number;
}

export interface SubjectState {
  subject: string;
  level: string;
  updated_at: number;
}

export interface BindingRow {
  a: string;
  b: string;
  proof: string;
  evidence: string;
  bound_at: number;
  revoked_at: number | null;
}

export interface CallRow {
  id: string;
  account_id: string;
  kind: string;
  subject: string | null;
  created_at: number;
}

export interface Stats {
  subjects: number;
  observations: number;
  bindings: number;
  profiles: number;
  accounts: number;
  calls: number;
}

export interface TrustStore {
  // accounts (billing) — same shape as the other connectors
  getAccount(id: string): Promise<Account | null>;
  ensureAccount(id: string, email: string | null, credits: number): Promise<Account>;
  addCredits(id: string, credits: number): Promise<void>;
  decrementCredit(id: string): Promise<void>;
  setPlan(id: string, plan: string, stripeCustomer?: string | null): Promise<void>;
  findAccountByCustomer(customerId: string): Promise<Account | null>;
  countCallsSince(accountId: string, since: number): Promise<number>;
  recordCall(call: CallRow): Promise<void>;
  // trust graph
  touchSubject(subject: string, now: number): Promise<void>;
  getState(subject: string): Promise<SubjectState | null>;
  setState(subject: string, level: string, now: number): Promise<void>;
  /** Idempotent on (source, ref). Returns false when the observation already exists. */
  addObservation(input: ObservationInput): Promise<boolean>;
  listObservations(subjects: string[], limit: number): Promise<Observation[]>;
  /** Recent subject states (for the leaderboard); ranking happens in the caller. */
  listStates(limit: number): Promise<SubjectState[]>;
  addBinding(row: Omit<BindingRow, "revoked_at">): Promise<boolean>;
  listBindings(): Promise<BindingRow[]>;
  revokeBinding(a: string, b: string): Promise<boolean>;
  saveVerdict(subject: string, profileJson: string, expiresAt: number): Promise<void>;
  getVerdict(subject: string): Promise<{ profile_json: string; expires_at: number } | null>;
  stats(): Promise<Stats>;
}

type Row = Record<string, unknown>;

export const observationId = (source: string, ref: string): string => `${source}:${ref}`;

const asAccount = (r: Row): Account => ({
  id: String(r.id),
  email: r.email == null ? null : String(r.email),
  credits: Number(r.credits),
  plan: String(r.plan),
  stripe_customer: r.stripe_customer == null ? null : String(r.stripe_customer),
  created_at: Number(r.created_at),
});

const asObservation = (r: Row): Observation => ({
  id: String(r.id),
  subject: String(r.subject),
  source: String(r.source),
  kind: String(r.kind),
  ref: String(r.ref),
  value: r.value == null ? null : Number(r.value),
  meta_json: String(r.meta_json ?? "{}"),
  observed_at: Number(r.observed_at),
});

// ---------- D1 ----------

/** Minimal D1 surface so the store can be tested without a Worker. */
export interface D1Like {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      first<T = Row>(): Promise<T | null>;
      all<T = Row>(): Promise<{ results: T[] }>;
      run(): Promise<unknown>;
    };
  };
}

export function d1Store(db: D1Like): TrustStore {
  const first = async <T = Row>(sql: string, ...args: unknown[]): Promise<T | null> =>
    (await db.prepare(sql).bind(...args).first<T>()) ?? null;
  const run = async (sql: string, ...args: unknown[]): Promise<boolean> => {
    const res = (await db.prepare(sql).bind(...args).run()) as { meta?: { changes?: number } } | undefined;
    return (res?.meta?.changes ?? 1) > 0;
  };
  return {
    async getAccount(id) {
      const r = await first("SELECT * FROM tr_accounts WHERE id = ?", id);
      return r ? asAccount(r) : null;
    },
    async ensureAccount(id, email, credits) {
      const existing = await first("SELECT * FROM tr_accounts WHERE id = ?", id);
      if (existing) return asAccount(existing);
      const created_at = Date.now();
      await run(
        "INSERT OR IGNORE INTO tr_accounts (id, email, credits, plan, created_at) VALUES (?, ?, ?, 'free', ?)",
        id,
        email,
        credits,
        created_at,
      );
      return (await first<Row>("SELECT * FROM tr_accounts WHERE id = ?", id).then((r) => (r ? asAccount(r) : null))) ?? {
        id,
        email,
        credits,
        plan: "free",
        stripe_customer: null,
        created_at,
      };
    },
    async addCredits(id, credits) {
      await run("UPDATE tr_accounts SET credits = credits + ? WHERE id = ?", Math.max(0, Math.floor(credits)), id);
    },
    async decrementCredit(id) {
      await run("UPDATE tr_accounts SET credits = MAX(credits - 1, 0) WHERE id = ?", id);
    },
    async setPlan(id, plan, stripeCustomer) {
      if (stripeCustomer) await run("UPDATE tr_accounts SET plan = ?, stripe_customer = ? WHERE id = ?", plan, stripeCustomer, id);
      else await run("UPDATE tr_accounts SET plan = ? WHERE id = ?", plan, id);
    },
    async findAccountByCustomer(customerId) {
      const r = await first("SELECT * FROM tr_accounts WHERE stripe_customer = ?", customerId);
      return r ? asAccount(r) : null;
    },
    async countCallsSince(accountId, since) {
      const r = await first<{ n: number }>("SELECT COUNT(*) AS n FROM tr_calls WHERE account_id = ? AND created_at >= ?", accountId, since);
      return Number(r?.n ?? 0);
    },
    async recordCall(call) {
      await run(
        "INSERT INTO tr_calls (id, account_id, kind, subject, created_at) VALUES (?, ?, ?, ?, ?)",
        call.id,
        call.account_id,
        call.kind,
        call.subject,
        call.created_at,
      );
    },
    async touchSubject(subject, now) {
      await run("INSERT OR IGNORE INTO tr_subjects (subject, created_at) VALUES (?, ?)", subject, now);
    },
    async getState(subject) {
      const r = await first<Row>("SELECT subject, level, updated_at FROM tr_state WHERE subject = ?", subject);
      if (!r) return null;
      return { subject: String(r.subject), level: String(r.level), updated_at: Number(r.updated_at) };
    },
    async setState(subject, level, now) {
      await run(
        "INSERT INTO tr_state (subject, level, updated_at) VALUES (?, ?, ?) ON CONFLICT(subject) DO UPDATE SET level = excluded.level, updated_at = excluded.updated_at",
        subject,
        level,
        now,
      );
    },
    async addObservation(input) {
      const id = observationId(input.source, input.ref);
      return run(
        "INSERT OR IGNORE INTO tr_observations (id, subject, source, kind, ref, value, meta_json, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        input.subject,
        input.source,
        input.kind,
        input.ref,
        input.value ?? null,
        JSON.stringify(input.meta ?? {}),
        input.observed_at ?? Date.now(),
      );
    },
    async listObservations(subjects, limit) {
      if (subjects.length === 0) return [];
      const holes = subjects.map(() => "?").join(",");
      const res = await db
        .prepare(
          `SELECT * FROM tr_observations WHERE subject IN (${holes}) ORDER BY observed_at DESC LIMIT ?`,
        )
        .bind(...subjects, Math.max(1, Math.floor(limit)))
        .all<Row>();
      return (res.results ?? []).map(asObservation);
    },
    async listStates(limit) {
      const res = await db
        .prepare("SELECT subject, level, updated_at FROM tr_state ORDER BY updated_at DESC LIMIT ?")
        .bind(Math.max(1, Math.floor(limit)))
        .all<Row>();
      return (res.results ?? []).map((r) => ({
        subject: String(r.subject),
        level: String(r.level),
        updated_at: Number(r.updated_at),
      }));
    },
    async addBinding(row) {
      return run(
        "INSERT INTO tr_bindings (a, b, proof, evidence, bound_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL) " +
          "ON CONFLICT(a, b) DO UPDATE SET proof = excluded.proof, evidence = excluded.evidence, bound_at = excluded.bound_at, revoked_at = NULL",
        row.a,
        row.b,
        row.proof,
        row.evidence,
        row.bound_at,
      );
    },
    async listBindings() {
      const res = await db.prepare("SELECT * FROM tr_bindings WHERE revoked_at IS NULL").bind().all<Row>();
      return (res.results ?? []).map((r) => ({
        a: String(r.a),
        b: String(r.b),
        proof: String(r.proof),
        evidence: String(r.evidence ?? ""),
        bound_at: Number(r.bound_at),
        revoked_at: r.revoked_at == null ? null : Number(r.revoked_at),
      }));
    },
    async revokeBinding(a, b) {
      return run("UPDATE tr_bindings SET revoked_at = ? WHERE a = ? AND b = ? AND revoked_at IS NULL", Date.now(), a, b);
    },
    async saveVerdict(subject, profileJson, expiresAt) {
      await run(
        "INSERT INTO tr_verdicts (subject, profile_json, expires_at) VALUES (?, ?, ?) ON CONFLICT(subject) DO UPDATE SET profile_json = excluded.profile_json, expires_at = excluded.expires_at",
        subject,
        profileJson,
        expiresAt,
      );
    },
    async getVerdict(subject) {
      const r = await first<Row>("SELECT profile_json, expires_at FROM tr_verdicts WHERE subject = ?", subject);
      if (!r) return null;
      return { profile_json: String(r.profile_json), expires_at: Number(r.expires_at) };
    },
    async stats() {
      const one = async (sql: string): Promise<number> => Number((await first<{ n: number }>(sql))?.n ?? 0);
      return {
        subjects: await one("SELECT COUNT(*) AS n FROM tr_subjects"),
        observations: await one("SELECT COUNT(*) AS n FROM tr_observations"),
        bindings: await one("SELECT COUNT(*) AS n FROM tr_bindings WHERE revoked_at IS NULL"),
        profiles: await one("SELECT COUNT(*) AS n FROM tr_verdicts"),
        accounts: await one("SELECT COUNT(*) AS n FROM tr_accounts"),
        calls: await one("SELECT COUNT(*) AS n FROM tr_calls"),
      };
    },
  };
}

// ---------- memory ----------

export function memoryStore(now: () => number = Date.now): TrustStore {
  const accounts = new Map<string, Account>();
  const subjects = new Map<string, number>();
  const state = new Map<string, SubjectState>();
  const observations = new Map<string, Observation>();
  const bindings = new Map<string, BindingRow>();
  const verdicts = new Map<string, { profile_json: string; expires_at: number }>();
  const calls = new Map<string, CallRow>();
  const key = (a: string, b: string): string => `${a}\u0000${b}`;
  return {
    async getAccount(id) {
      return accounts.get(id) ?? null;
    },
    async ensureAccount(id, email, credits) {
      const found = accounts.get(id);
      if (found) return found;
      const acct: Account = { id, email, credits, plan: "free", stripe_customer: null, created_at: now() };
      accounts.set(id, acct);
      return acct;
    },
    async addCredits(id, credits) {
      const a = accounts.get(id);
      if (a) accounts.set(id, { ...a, credits: a.credits + Math.max(0, Math.floor(credits)) });
    },
    async decrementCredit(id) {
      const a = accounts.get(id);
      if (a) accounts.set(id, { ...a, credits: Math.max(a.credits - 1, 0) });
    },
    async setPlan(id, plan, stripeCustomer) {
      const a = accounts.get(id);
      if (a) accounts.set(id, { ...a, plan, stripe_customer: stripeCustomer ?? a.stripe_customer });
    },
    async findAccountByCustomer(customerId) {
      return [...accounts.values()].find((a) => a.stripe_customer === customerId) ?? null;
    },
    async countCallsSince(accountId, since) {
      return [...calls.values()].filter((c) => c.account_id === accountId && c.created_at >= since).length;
    },
    async recordCall(call) {
      calls.set(call.id, { ...call });
    },
    async touchSubject(subject, at) {
      if (!subjects.has(subject)) subjects.set(subject, at);
    },
    async getState(subject) {
      return state.get(subject) ?? null;
    },
    async setState(subject, level, at) {
      state.set(subject, { subject, level, updated_at: at });
    },
    async addObservation(input) {
      const id = observationId(input.source, input.ref);
      if (observations.has(id)) return false;
      observations.set(id, {
        id,
        subject: input.subject,
        source: input.source,
        kind: input.kind,
        ref: input.ref,
        value: input.value ?? null,
        meta_json: JSON.stringify(input.meta ?? {}),
        observed_at: input.observed_at ?? now(),
      });
      if (!subjects.has(input.subject)) subjects.set(input.subject, input.observed_at ?? now());
      return true;
    },
    async listObservations(subjectList, limit) {
      const set = new Set(subjectList);
      return [...observations.values()]
        .filter((o) => set.has(o.subject))
        .sort((a, b) => b.observed_at - a.observed_at)
        .slice(0, Math.max(1, Math.floor(limit)));
    },
    async listStates(limit) {
      return [...state.values()]
        .sort((a, b) => b.updated_at - a.updated_at)
        .slice(0, Math.max(1, Math.floor(limit)));
    },
    async addBinding(row) {
      bindings.set(key(row.a, row.b), { ...row, revoked_at: null });
      return true;
    },
    async listBindings() {
      return [...bindings.values()].filter((b) => b.revoked_at === null).sort((x, y) => y.bound_at - x.bound_at);
    },
    async revokeBinding(a, b) {
      const found = bindings.get(key(a, b));
      if (!found || found.revoked_at !== null) return false;
      bindings.set(key(a, b), { ...found, revoked_at: now() });
      return true;
    },
    async saveVerdict(subject, profileJson, expiresAt) {
      verdicts.set(subject, { profile_json: profileJson, expires_at: expiresAt });
    },
    async getVerdict(subject) {
      return verdicts.get(subject) ?? null;
    },
    async stats() {
      return {
        subjects: subjects.size,
        observations: observations.size,
        bindings: [...bindings.values()].filter((b) => b.revoked_at === null).length,
        profiles: verdicts.size,
        accounts: accounts.size,
        calls: calls.size,
      };
    },
  };
}