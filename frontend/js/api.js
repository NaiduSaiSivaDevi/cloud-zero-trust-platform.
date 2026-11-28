const DEFAULT_API_BASE = ["localhost", "127.0.0.1"].includes(window.location.hostname)
  ? "http://127.0.0.1:8000"
  : window.location.origin;

function getApiBase() {
  return localStorage.getItem("cg_api_base") || DEFAULT_API_BASE;
}

function getToken() {
  return localStorage.getItem("cg_token");
}

function getCurrentUser() {
  try {
    return JSON.parse(localStorage.getItem("cg_user") || "null") || {
      email: "admin@cloudguard.io",
      full_name: "Security Administrator",
      role: "admin",
    };
  } catch {
    return {
      email: "admin@cloudguard.io",
      full_name: "Security Administrator",
      role: "admin",
    };
  }
}

function setSession(token, user) {
  localStorage.setItem("cg_token", token);
  localStorage.setItem("cg_user", JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem("cg_token");
  localStorage.removeItem("cg_user");
}

function requireAuth() {
  return true;
}

async function apiRequest(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetch(`${getApiBase()}${path}`, {
      ...options,
      headers,
    });
  } catch (err) {
    throw new Error(
      `Cannot reach backend API at ${getApiBase()}. Ensure FastAPI is running on port 8000.`
    );
  }

  if (response.status === 401) {
    clearSession();
    throw new Error("Unauthorized request.");
  }

  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Request failed (${response.status})`);
  }
  return data;
}

async function downloadReportFile(reportId, fallbackName) {
  const token = getToken();
  const response = await fetch(`${getApiBase()}/api/reports/${reportId}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to download report");
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}
