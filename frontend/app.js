/*
File: app.js
Purpose: Frontend controller for the Assignment 3 prototype.
Security note: No inline onclick handlers are used. Event listeners are attached here so the backend can keep a strict Content Security Policy.
*/

const API = "/api";

function $(id) {
  return document.getElementById(id);
}

function show(data, id = "output") {
  const box = $(id);
  if (!box) return;
  if (typeof data === "string") {
    box.textContent = data;
  } else {
    box.textContent = JSON.stringify(data, null, 2);
  }
  if (id === "output") box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function getToken() {
  return localStorage.getItem("token");
}

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function updateSessionInfo() {
  const info = $("sessionInfo");
  if (!info) return;
  const t = getToken();
  if (!t) {
    info.textContent = "Not logged in";
    return;
  }
  info.textContent = `Logged in as ${localStorage.getItem("name") || "user"} (${localStorage.getItem("role") || "role"}) user_id=${localStorage.getItem("user_id") || "?"}`;
}

function readableError(error) {
  if (typeof error === "string") return error;
  if (error && error.detail) {
    if (Array.isArray(error.detail)) {
      return error.detail.map(item => {
        const place = item.loc ? item.loc.join(".") : "input";
        return `${place}: ${item.msg}`;
      }).join("\n");
    }
    return error.detail;
  }
  return error || "Unknown error";
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}), ...authHeaders() };
  const res = await fetch(API + path, { ...options, headers });
  const contentType = res.headers.get("content-type") || "";

  if (!res.ok) {
    let problem;
    if (contentType.includes("application/json")) {
      problem = await res.json();
    } else {
      problem = await res.text();
    }
    throw problem;
  }

  if (contentType.includes("application/json")) return res.json();
  return res.blob();
}

async function registerUser(event) {
  event.preventDefault();
  try {
    const payload = {
      name: $("regName").value.trim(),
      email: $("regEmail").value.trim(),
      password: $("regPassword").value,
      role: $("regRole").value
    };
    const data = await api("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    show({ message: "Registered successfully. Now login with this email and password.", user: data });
  } catch (e) {
    show(readableError(e));
  }
}

async function loginUser(event) {
  event.preventDefault();
  try {
    const data = await api("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: $("loginEmail").value.trim(),
        password: $("loginPassword").value
      })
    });
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("role", data.role);
    localStorage.setItem("name", data.name);
    localStorage.setItem("user_id", data.user_id);
    updateSessionInfo();
    show({ message: "Login successful", ...data });
  } catch (e) {
    show(readableError(e));
  }
}

function logoutUser() {
  localStorage.clear();
  updateSessionInfo();
  show("Logged out. Browser token removed.");
}

async function createCase(event) {
  event.preventDefault();
  try {
    const data = await api("/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_title: $("caseTitle").value.trim(),
        client_id: Number($("caseClientId").value)
      })
    });
    show(data, "caseOutput");
    show(`Case created successfully. Case ID = ${data.id}`);
  } catch (e) {
    show(readableError(e));
  }
}

async function listCases() {
  try {
    show(await api("/cases"), "caseOutput");
  } catch (e) {
    show(readableError(e));
  }
}

async function uploadDocument(event) {
  event.preventDefault();
  try {
    const file = $("uploadFile").files[0];
    if (!file) return show("Choose a file first.");
    const caseId = $("uploadCaseId").value;
    if (!caseId) return show("Enter a Case ID first.");

    const form = new FormData();
    form.append("file", file);
    const data = await api(`/documents/upload?case_id=${encodeURIComponent(caseId)}`, {
      method: "POST",
      body: form
    });
    show({ message: "Document uploaded, scanned, encrypted, and saved successfully.", document: data });
  } catch (e) {
    show(readableError(e));
  }
}

async function listDocuments() {
  try {
    const docs = await api("/documents");
    const container = $("documents");
    container.innerHTML = "";
    if (!docs.length) {
      container.textContent = "No visible documents for this logged-in user.";
      return;
    }

    docs.forEach(doc => {
      const div = document.createElement("div");
      div.className = "item";
      div.innerHTML = `<b>#${doc.id} ${escapeHtml(doc.original_filename)}</b><br>Case: ${doc.case_id}<br>Uploader: ${doc.uploaded_by_id}<br>SHA-256: ${doc.file_hash}<br>Scan: ${doc.scan_status}<br>`;
      const downloadBtn = document.createElement("button");
      downloadBtn.type = "button";
      downloadBtn.textContent = "Download";
      downloadBtn.addEventListener("click", () => downloadDocument(doc.id, doc.original_filename));
      div.appendChild(downloadBtn);
      container.appendChild(div);
    });
  } catch (e) {
    show(readableError(e));
  }
}

async function downloadDocument(id, filename) {
  try {
    const blob = await api(`/documents/${id}/download`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || `document-${id}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    show(`Download started for document #${id}`);
  } catch (e) {
    show(readableError(e));
  }
}

async function requestAccess(event) {
  event.preventDefault();
  try {
    const data = await api(`/permissions/documents/${$("requestDocId").value}/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: $("requestReason").value.trim() || null })
    });
    show({ message: "Permission request sent to the lawyer.", request: data });
  } catch (e) {
    show(readableError(e));
  }
}

async function shareDocument(event) {
  event.preventDefault();
  try {
    const data = await api(`/documents/${$("shareDocId").value}/share`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_user_id: Number($("shareUserId").value),
        permission_type: $("sharePermission").value
      })
    });
    show(data);
  } catch (e) {
    show(readableError(e));
  }
}

async function listPermissionRequests() {
  try {
    const reqs = await api("/permissions/requests");
    const container = $("requests");
    container.innerHTML = "";
    if (!reqs.length) {
      container.textContent = "No permission requests for this lawyer.";
      return;
    }

    reqs.forEach(r => {
      const div = document.createElement("div");
      div.className = "item";
      div.innerHTML = `<b>Request #${r.id}</b><br>Doc: ${r.document_id}<br>By user: ${r.requested_by_id}<br>Status: ${r.status}<br>Reason: ${escapeHtml(r.reason || "")}<br>`;
      if (r.status === "PENDING") {
        const approve = document.createElement("button");
        approve.type = "button";
        approve.textContent = "Approve";
        approve.addEventListener("click", () => reviewRequest(r.id, "approve"));
        const reject = document.createElement("button");
        reject.type = "button";
        reject.textContent = "Reject";
        reject.className = "secondary";
        reject.addEventListener("click", () => reviewRequest(r.id, "reject"));
        div.appendChild(approve);
        div.appendChild(reject);
      }
      container.appendChild(div);
    });
  } catch (e) {
    show(readableError(e));
  }
}

async function reviewRequest(id, action) {
  try {
    const data = await api(`/permissions/requests/${id}/${action}`, { method: "PATCH" });
    show(data);
    await listPermissionRequests();
  } catch (e) {
    show(readableError(e));
  }
}

async function listUsers() {
  try {
    show(await api("/admin/users"), "adminOutput");
  } catch (e) {
    show(readableError(e));
  }
}

async function listAuditLogs() {
  try {
    show(await api("/admin/audit-logs?limit=50"), "adminOutput");
  } catch (e) {
    show(readableError(e));
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#039;",
    "\"": "&quot;"
  }[ch]));
}

function bindEvents() {
  $("registerForm").addEventListener("submit", registerUser);
  $("loginForm").addEventListener("submit", loginUser);
  $("logoutBtn").addEventListener("click", logoutUser);
  $("caseForm").addEventListener("submit", createCase);
  $("listCasesBtn").addEventListener("click", listCases);
  $("uploadForm").addEventListener("submit", uploadDocument);
  $("listDocumentsBtn").addEventListener("click", listDocuments);
  $("requestAccessForm").addEventListener("submit", requestAccess);
  $("shareForm").addEventListener("submit", shareDocument);
  $("listPermissionRequestsBtn").addEventListener("click", listPermissionRequests);
  $("listUsersBtn").addEventListener("click", listUsers);
  $("listAuditLogsBtn").addEventListener("click", listAuditLogs);
}

bindEvents();
updateSessionInfo();
