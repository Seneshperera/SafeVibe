import { useEffect, useState } from "react";
import { ApiError, checkHealth, createAnalysis, deleteAnalysis, getDisclosure } from "./api.js";
import SubmitForm from "./SubmitForm.jsx";
import ResultView from "./ResultView.jsx";

export default function App() {
  const [server, setServer] = useState("checking"); // checking | waking | ready | down
  const [disclosure, setDisclosure] = useState(null);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState([]);
  const [banner, setBanner] = useState("");
  const [result, setResult] = useState(null);

  // free hosts sleep when idle: tell the user instead of showing a blank page
  useEffect(() => {
    let cancelled = false;
    const slow = setTimeout(() => !cancelled && setServer((s) => (s === "checking" ? "waking" : s)), 2500);
    (async () => {
      for (let i = 0; i < 12 && !cancelled; i++) {
        try {
          await checkHealth();
          if (!cancelled) setServer("ready");
          getDisclosure().then((d) => !cancelled && setDisclosure(d)).catch(() => {});
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 5000));
        }
      }
      if (!cancelled) setServer("down");
    })();
    return () => { cancelled = true; clearTimeout(slow); };
  }, []);

  async function analyse(payload) {
    setBusy(true); setErrors([]); setBanner("");
    try {
      setResult(await createAnalysis(payload));
      window.scrollTo({ top: 0 });
    } catch (e) {
      if (e instanceof ApiError && e.fieldErrors.length) setErrors(e.fieldErrors);
      else setBanner(e.message || "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    try {
      await deleteAnalysis(result.request_id);
      setResult(null);
      setBanner("Your submission and its result were deleted.");
    } catch (e) {
      setBanner(e.message || "Could not delete. Try again.");
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-6">
      <a href="#main" className="sr-only focus:not-sr-only focus:underline">Skip to content</a>
      <header className="mb-6">
        <h1 className="text-3xl font-bold">SafeVibe</h1>
        <p className="text-slate-700">Check a suspicious message, link, chat or email, and see exactly why it looks risky.</p>
      </header>

      <main id="main">
        {server !== "ready" && (
          <div role="status" className="mb-4 rounded-md border border-blue-300 bg-blue-50 p-3 text-sm">
            {server === "checking" && "Connecting to the server…"}
            {server === "waking" && "Waking up the server. This can take up to a minute the first time. Please wait."}
            {server === "down" && "The server is not responding. Please try again in a few minutes."}
          </div>
        )}
        {banner && <div role="alert" className="mb-4 rounded-md border border-red-300 bg-red-50 p-3 text-sm font-medium text-red-900">{banner}</div>}

        {result ? (
          <ResultView result={result} onDelete={remove} onReset={() => { setResult(null); setBanner(""); }} />
        ) : (
          <>
            <SubmitForm onSubmit={analyse} busy={busy} errors={errors} disclosure={disclosure} />
            {busy && <p role="status" className="mt-3 text-sm">Analysing, please wait…</p>}
          </>
        )}
      </main>

      <footer className="mt-10 border-t pt-4 text-xs text-slate-600">
        SafeVibe is a university research prototype and decision-support tool. It cannot guarantee that anything is safe.
      </footer>
    </div>
  );
}
