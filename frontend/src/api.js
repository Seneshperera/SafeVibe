const BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message, status, fieldErrors = []) {
    super(message);
    this.status = status;
    this.fieldErrors = fieldErrors; // [{field, message}]
  }
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(BASE + path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch {
    throw new ApiError("Could not reach the SafeVibe server. Check your connection and try again.", 0);
  }
  if (res.status === 204) return null;
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    // our input manager: {detail, errors:[{field,message}]}; FastAPI/pydantic: {detail:[{loc,msg}]}
    let fieldErrors = [];
    if (body?.errors) fieldErrors = body.errors;
    else if (Array.isArray(body?.detail))
      fieldErrors = body.detail.map((d) => ({ field: (d.loc || []).slice(1).join("."), message: d.msg }));
    const msg = typeof body?.detail === "string" ? body.detail : "The request could not be processed.";
    throw new ApiError(msg, res.status, fieldErrors);
  }
  return body;
}

export const checkHealth = () => request("/health");
export const getDisclosure = () => request("/api/v1/disclosure");
export const createAnalysis = (payload) =>
  request("/api/v1/analyses", { method: "POST", body: JSON.stringify(payload) });
export const deleteAnalysis = (id) => request(`/api/v1/analyses/${id}`, { method: "DELETE" });
export const sendFeedback = (id, payload) =>
  request(`/api/v1/analyses/${id}/feedback`, { method: "POST", body: JSON.stringify(payload) });
