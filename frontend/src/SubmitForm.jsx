import { useState } from "react";

const TABS = [
  { id: "text", label: "Message" },
  { id: "urls", label: "Links" },
  { id: "conversation", label: "Conversation" },
  { id: "headers", label: "Email headers" },
];

function fieldError(errors, prefix) {
  return errors.filter((e) => e.field === prefix || e.field.startsWith(prefix + "[") || e.field === "__root__");
}

export default function SubmitForm({ onSubmit, busy, errors, disclosure }) {
  const [tab, setTab] = useState("text");
  const [text, setText] = useState("");
  const [urls, setUrls] = useState("");
  const [convo, setConvo] = useState(["", "", ""]);
  const [headers, setHeaders] = useState("");
  const [allowExternal, setAllowExternal] = useState(false);

  const filledConvo = convo.filter((m) => m.trim());
  const urlList = urls.split("\n").map((u) => u.trim()).filter(Boolean);
  const counts = {
    text: text.trim() ? "added" : "",
    urls: urlList.length ? `${urlList.length}` : "",
    conversation: filledConvo.length ? `${filledConvo.length}` : "",
    headers: headers.trim() ? "added" : "",
  };
  const hasInput = text.trim() || urlList.length || filledConvo.length || headers.trim();

  function submit(e) {
    e.preventDefault();
    onSubmit({
      text: text.trim() ? text : null,
      urls: urlList,
      conversation: filledConvo,
      email_headers: headers.trim() ? headers : null,
      allow_external: allowExternal,
    });
  }

  function onTabKey(e, i) {
    if (e.key === "ArrowRight") document.getElementById(`tab-${TABS[(i + 1) % TABS.length].id}`).focus();
    if (e.key === "ArrowLeft") document.getElementById(`tab-${TABS[(i + TABS.length - 1) % TABS.length].id}`).focus();
  }

  const box =
    "w-full rounded-md border border-slate-400 bg-white p-3 text-base leading-relaxed placeholder:text-slate-500";

  return (
    <form onSubmit={submit} className="space-y-5" aria-busy={busy} noValidate>
      <div className="rounded-md border-l-4 border-amber-600 bg-amber-50 p-3 text-sm">
        <strong>Never enter real passwords, OTPs, card or bank details.</strong> Paste only the suspicious message
        itself. You can add several kinds of evidence together; each tab below is optional.
      </div>

      <div role="tablist" aria-label="Type of evidence" className="flex flex-wrap gap-2">
        {TABS.map((t, i) => (
          <button
            key={t.id}
            id={`tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            onKeyDown={(e) => onTabKey(e, i)}
            className={`rounded-md border px-4 py-2 text-sm font-medium ${
              tab === t.id ? "border-blue-800 bg-blue-800 text-white" : "border-slate-400 bg-white hover:bg-slate-100"
            }`}
          >
            {t.label}
            {counts[t.id] && (
              <span className="ml-2 rounded bg-white/90 px-1.5 text-xs font-semibold text-blue-900">
                {counts[t.id] === "added" ? "✓" : counts[t.id]}
              </span>
            )}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "text" && (
          <div>
            <label htmlFor="text" className="mb-1 block font-medium">Suspicious message text</label>
            <textarea id="text" rows={7} value={text} onChange={(e) => setText(e.target.value)}
              placeholder="Paste the SMS, email body or chat message here" className={box} maxLength={5000} />
            <p className="mt-1 text-sm text-slate-600">{text.length}/5000 characters</p>
            <Errors list={fieldError(errors, "text")} />
          </div>
        )}
        {tab === "urls" && (
          <div>
            <label htmlFor="urls" className="mb-1 block font-medium">Links (one per line, up to 10)</label>
            <textarea id="urls" rows={5} value={urls} onChange={(e) => setUrls(e.target.value)}
              placeholder="http://example.com/login" className={`${box} font-mono text-sm`} />
            <p className="mt-1 text-sm text-slate-600">
              SafeVibe never opens these links. Do not open them yourself to check.
            </p>
            <Errors list={fieldError(errors, "urls")} />
          </div>
        )}
        {tab === "conversation" && (
          <fieldset>
            <legend className="mb-1 font-medium">Messages in order (oldest first)</legend>
            <p className="mb-2 text-sm text-slate-600">At least 3 messages are needed for reliable pattern checks.</p>
            <ol className="space-y-2">
              {convo.map((m, i) => (
                <li key={i} className="flex gap-2">
                  <label htmlFor={`m-${i}`} className="w-8 pt-3 text-sm font-semibold text-slate-700">#{i + 1}</label>
                  <textarea id={`m-${i}`} rows={2} value={m} className={box}
                    onChange={(e) => setConvo(convo.map((x, j) => (j === i ? e.target.value : x)))} />
                  <button type="button" aria-label={`Remove message ${i + 1}`}
                    disabled={convo.length <= 1}
                    onClick={() => setConvo(convo.filter((_, j) => j !== i))}
                    className="self-start rounded border border-slate-400 px-2 py-2 text-sm disabled:opacity-40">✕</button>
                </li>
              ))}
            </ol>
            <button type="button" onClick={() => setConvo([...convo, ""])} disabled={convo.length >= 50}
              className="mt-2 rounded border border-slate-400 bg-white px-3 py-1.5 text-sm">+ Add message</button>
            <Errors list={fieldError(errors, "conversation")} />
          </fieldset>
        )}
        {tab === "headers" && (
          <div>
            <label htmlFor="headers" className="mb-1 block font-medium">Raw email headers</label>
            <textarea id="headers" rows={8} value={headers} onChange={(e) => setHeaders(e.target.value)}
              placeholder={"From: ...\nReturn-Path: ...\nAuthentication-Results: ..."}
              className={`${box} font-mono text-sm`} />
            <p className="mt-1 text-sm text-slate-600">
              In Gmail: open the email, ⋮ menu → "Show original". Paste only the header lines.
            </p>
            <Errors list={fieldError(errors, "email_headers")} />
          </div>
        )}
      </div>

      <Errors list={errors.filter((e) => e.field === "__root__")} />

      <fieldset className="rounded-md border border-slate-300 bg-white p-4">
        <legend className="px-1 font-medium">Data sharing</legend>
        <label className="flex items-start gap-3">
          <input type="checkbox" checked={allowExternal} onChange={(e) => setAllowExternal(e.target.checked)}
            className="mt-1 h-5 w-5" />
          <span>
            Also check links with external security services (optional).
            <span className="mt-1 block text-sm text-slate-700">
              {disclosure
                ? `If enabled, only this is shared: ${disclosure.what_is_shared} ${
                    disclosure.enabled_services?.length
                      ? `Services configured: ${disclosure.enabled_services.join(", ")}.`
                      : "No external services are configured on this server yet."}`
                : "Only the link (without its query string) is sent. Message text and conversations are never shared."}
            </span>
          </span>
        </label>
      </fieldset>

      <button type="submit" disabled={busy || !hasInput}
        className="rounded-md bg-blue-800 px-6 py-3 text-base font-semibold text-white hover:bg-blue-900 disabled:cursor-not-allowed disabled:opacity-50">
        {busy ? "Analysing…" : "Analyse"}
      </button>
      {!hasInput && <p className="text-sm text-slate-600">Add some text, a link, a conversation or headers first.</p>}
    </form>
  );
}

function Errors({ list }) {
  if (!list.length) return null;
  return (
    <ul role="alert" className="mt-2 space-y-1 text-sm font-medium text-red-800">
      {list.map((e, i) => (
        <li key={i}>⚠ {e.field && e.field !== "__root__" ? `${e.field}: ` : ""}{e.message}</li>
      ))}
    </ul>
  );
}
