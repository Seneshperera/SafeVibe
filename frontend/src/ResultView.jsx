import { useState } from "react";
import { sendFeedback } from "./api.js";

const TIER = {
  "Low Risk": { icon: "✔", ring: "border-emerald-700 bg-emerald-50", text: "text-emerald-900",
    blurb: "No major warning signs were found. This does NOT mean it is safe." },
  Suspicious: { icon: "⚠", ring: "border-amber-600 bg-amber-50", text: "text-amber-900",
    blurb: "Some warning signs need checking before you act." },
  "High Risk": { icon: "✖", ring: "border-orange-700 bg-orange-50", text: "text-orange-900",
    blurb: "Several warning signs suggest probable fraud or phishing." },
  Critical: { icon: "⛔", ring: "border-red-800 bg-red-50", text: "text-red-900",
    blurb: "Strong evidence of phishing, impersonation or fraud." },
};

const FAMILY = { content: "Message wording", url: "Link", sender: "Sender", domain: "Reputation",
  conversation: "Conversation", image: "Screenshot" };

function Section({ title, children, id }) {
  return (
    <section aria-labelledby={id} className="rounded-md border border-slate-300 bg-white p-4">
      <h3 id={id} className="mb-2 text-lg font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function origin(e) {
  if (e.source_type === "external") return { label: "External service", cls: "bg-purple-100 text-purple-900" };
  if (e.details?.scope === "sequence") return { label: "Conversation pattern", cls: "bg-sky-100 text-sky-900" };
  return { label: "SafeVibe rule", cls: "bg-slate-200 text-slate-900" };
}

export default function ResultView({ result, onDelete, onReset }) {
  const [mode, setMode] = useState("plain");
  const [confirmDel, setConfirmDel] = useState(false);
  const a = result.assessment;
  const t = TIER[a.tier] || TIER.Suspicious;
  const urls = result.artefacts.filter((x) => x.type === "url");

  return (
    <div className="space-y-5" aria-live="polite">
      {/* IR-UI-005: persistent limitation, always visible */}
      <div role="note" className="rounded-md border-l-4 border-slate-700 bg-slate-100 p-3 text-sm font-medium">
        A "Low Risk" result is not proof that something is safe. SafeVibe does not guarantee safety.
      </div>

      <div className={`rounded-lg border-2 p-5 ${t.ring}`}>
        <div className="flex flex-wrap items-center gap-4">
          <span aria-hidden="true" className="text-4xl">{t.icon}</span>
          <div>
            <p className={`text-2xl font-bold ${t.text}`}>{a.tier}</p>
            <p className="text-slate-800">{t.blurb}</p>
          </div>
          <div className="ml-auto text-right">
            <p className="text-3xl font-bold">{a.score}<span className="text-lg font-medium">/100</span></p>
            <p className="text-xs text-slate-700">Risk score</p>
          </div>
        </div>
        <div className="mt-3 h-3 w-full rounded bg-white" role="img" aria-label={`Risk score ${a.score} out of 100`}>
          <div className="h-3 rounded bg-slate-800" style={{ width: `${a.score}%` }} />
        </div>
        {result.status === "partial" && (
          <p className="mt-3 text-sm font-medium">
            ⚠ Partial result: some checks were unavailable or incomplete (see Limitations).
          </p>
        )}
        {a.adjustments?.map((x, i) => <p key={i} className="mt-2 text-sm font-medium">ℹ {x}</p>)}
      </div>

      <Section title="What to do now" id="actions">
        <ul className="list-disc space-y-1 pl-5">
          {result.safe_actions.map((x, i) => <li key={i}>{x.action_text}</li>)}
        </ul>
        <p className="mt-2 text-sm text-slate-700">
          To verify, use the official app, website or phone number you already trust. Never open the suspicious link.
        </p>
      </Section>

      <Section title="Why this result" id="reasons">
        <div role="tablist" aria-label="Explanation level" className="mb-3 inline-flex overflow-hidden rounded border border-slate-400">
          {[["plain", "Plain language"], ["technical", "Technical"]].map(([id, label]) => (
            <button key={id} role="tab" aria-selected={mode === id} onClick={() => setMode(id)}
              className={`px-4 py-1.5 text-sm font-medium ${mode === id ? "bg-blue-800 text-white" : "bg-white"}`}>
              {label}
            </button>
          ))}
        </div>
        {result.evidence.length === 0 ? (
          <p>No warning signs were detected by the checks that ran. See Limitations below for what was not checked.</p>
        ) : (
          <ol className="space-y-3">
            {result.evidence.map((e, i) => {
              const o = origin(e);
              return (
                <li key={e.evidence_id} className="rounded border border-slate-200 p-3">
                  <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-semibold">#{i + 1}</span>
                    <span className={`rounded px-2 py-0.5 font-medium ${o.cls}`}>{o.label}</span>
                    <span className="rounded bg-slate-100 px-2 py-0.5">{FAMILY[e.signal_family] || e.signal_family}</span>
                    {e.details?.message_indexes && (
                      <span className="rounded bg-slate-100 px-2 py-0.5">
                        message{e.details.message_indexes.length > 1 ? "s" : ""} {e.details.message_indexes.map((n) => n + 1).join(", ")}
                      </span>
                    )}
                  </div>
                  <p>{mode === "plain" ? e.plain : e.technical}</p>
                  {e.matched_text && (
                    <p className="mt-1 text-sm text-slate-700">Matched: <q className="font-mono">{e.matched_text}</q></p>
                  )}
                  {mode === "technical" && (
                    <p className="mt-1 font-mono text-xs text-slate-600">
                      {e.rule_id} · {e.rule_version} · contribution {e.contribution}
                      {e.details?.queried_at && ` · queried ${e.details.queried_at}`}
                      {e.details?.query_scope && ` · scope: ${e.details.query_scope}`}
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
        )}
        {mode === "technical" && (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="mb-1 text-left font-medium">Score breakdown ({a.weights_version})</caption>
              <thead><tr className="border-b"><th className="py-1">Signal family</th><th>Family score (0–1)</th><th>Weight used</th></tr></thead>
              <tbody>
                {a.family_scores.map((f) => (
                  <tr key={f.family} className="border-b border-slate-100">
                    <td className="py-1">{FAMILY[f.family] || f.family}</td><td>{f.score}</td><td>{f.weight}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-1 text-xs text-slate-600">Score = 100 × Σ(weight × family score). Rules {a.rules_version}.</p>
          </div>
        )}
      </Section>

      <Section title="Limitations and uncertainty" id="limits">
        <ul className="list-disc space-y-1 pl-5">
          {a.limitations.map((l, i) => <li key={i}>{l}</li>)}
        </ul>
        {result.connectors.length > 0 && (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="mb-1 text-left font-medium">External services</caption>
              <tbody>
                {result.connectors.map((c) => (
                  <tr key={c.name} className="border-b border-slate-100">
                    <td className="py-1 pr-3 font-medium">{c.name.replace("_", " ")}</td>
                    <td className="pr-3">{c.status.replace("_", " ")}</td>
                    <td className="text-slate-700">{c.note || ""}{c.from_cache ? " (cached)" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {urls.length > 0 && (
        <Section title="Links analysed (never opened)" id="links">
          <ul className="space-y-2 text-sm">
            {urls.map((u) => (
              <li key={u.artefact_id}>
                <div>Submitted: <code className="break-all">{u.original}</code></div>
                <div>Analysed as: <code className="break-all">{u.canonical}</code></div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Feedback id={result.request_id} />

      <p className="text-sm text-slate-700">{result.disclaimer}</p>

      <div className="flex flex-wrap items-center gap-3 border-t pt-4">
        <button onClick={onReset} className="rounded-md bg-blue-800 px-5 py-2 font-semibold text-white">Check something else</button>
        {!confirmDel ? (
          <button onClick={() => setConfirmDel(true)} className="rounded-md border border-red-800 px-5 py-2 font-medium text-red-900">
            Delete my data
          </button>
        ) : (
          <span role="alertdialog" aria-label="Confirm delete" className="flex items-center gap-2 text-sm">
            This permanently removes what you submitted and this result.
            <button onClick={onDelete} className="rounded bg-red-800 px-3 py-1.5 font-semibold text-white">Yes, delete</button>
            <button onClick={() => setConfirmDel(false)} className="rounded border px-3 py-1.5">Cancel</button>
          </span>
        )}
      </div>
    </div>
  );
}

function Feedback({ id }) {
  const [understood, setUnderstood] = useState(null);
  const [rating, setRating] = useState(null);
  const [comment, setComment] = useState("");
  const [state, setState] = useState("idle"); // idle | sending | sent | error

  async function submit(e) {
    e.preventDefault();
    setState("sending");
    try {
      await sendFeedback(id, { understood, rating, comment: comment.trim() || null });
      setState("sent");
    } catch {
      setState("error");
    }
  }
  if (state === "sent") return <Section title="Feedback" id="fb"><p>Thank you, your feedback was recorded.</p></Section>;
  const can = understood !== null || rating !== null || comment.trim();
  return (
    <Section title="Was this clear?" id="fb">
      <form onSubmit={submit} className="space-y-3">
        <fieldset>
          <legend className="text-sm font-medium">Did you understand why you got this result?</legend>
          {[[true, "Yes"], [false, "No"]].map(([v, l]) => (
            <label key={l} className="mr-4 inline-flex items-center gap-1">
              <input type="radio" name="understood" checked={understood === v} onChange={() => setUnderstood(v)} /> {l}
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend className="text-sm font-medium">How easy was it to use? (1 = hard, 5 = easy)</legend>
          {[1, 2, 3, 4, 5].map((n) => (
            <label key={n} className="mr-3 inline-flex items-center gap-1">
              <input type="radio" name="rating" checked={rating === n} onChange={() => setRating(n)} /> {n}
            </label>
          ))}
        </fieldset>
        <div>
          <label htmlFor="comment" className="text-sm font-medium">Comment (optional, no personal details)</label>
          <textarea id="comment" rows={2} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)}
            className="mt-1 w-full rounded border border-slate-400 p-2" />
        </div>
        <button disabled={!can || state === "sending"} className="rounded border border-slate-600 px-4 py-1.5 disabled:opacity-50">
          Send feedback
        </button>
        {state === "error" && <p role="alert" className="text-sm text-red-800">Could not send feedback. Try again.</p>}
      </form>
    </Section>
  );
}
