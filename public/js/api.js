/* =====================================================================
   RizzAPI — thin wrapper over the real backend routes (src/server/index.js).
   NOTE: routes live at the ROOT, matching index.js.
   All calls are same-origin relative paths, served from /public.
   ===================================================================== */
(function () {
  let token = null;

  function setToken(t) { token = t; }
  function getToken() { return token; }

  function headers(withBody) {
    const h = {};
    if (withBody) h["Content-Type"] = "application/json";
    if (token) h["Authorization"] = "Bearer " + token;
    return h;
  }

  async function handle(res) {
    let data = null;
    const text = await res.text();
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error((data && data.error) || ("Request failed (" + res.status + ")"));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // Decode the integer user id out of the JWT payload (mirrors Client.cpp).
  function userIdFromToken(t) {
    try {
      const payload = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      const json = JSON.parse(decodeURIComponent(escape(atob(payload + "===".slice((payload.length + 3) % 4)))));
      return json.id;
    } catch (_) { return null; }
  }

  // ---------------- auth ----------------
  async function register(username, password, publicKey) {
    return handle(await fetch("/auth/register", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({ username, password, publicKey }),
    }));
  }

  async function login(username, password) {
    const data = await handle(await fetch("/auth/login", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({ username, password }),
    }));
    return data; // { token }
  }

  async function changePassword(currentPassword, newPassword) {
    return handle(await fetch("/auth/password", {
      method: "PUT",
      headers: headers(true),
      body: JSON.stringify({ currentPassword, newPassword }),
    }));
  }

  // ---------------- users ----------------
  async function updatePublicKey(publicKey) {
    return handle(await fetch("/users/pubkey", {
      method: "PUT",
      headers: headers(true),
      body: JSON.stringify({ publicKey }),
    }));
  }

  async function getPublicKey(userId) {
    return handle(await fetch("/users/" + encodeURIComponent(userId) + "/pubkey", {
      method: "GET",
      headers: headers(false),
    }));
  }

  // ---------------- messages ----------------
  async function sendMessage(to, encField, ciphertext) {
    return handle(await fetch("/messages", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({ to, enc: encField, ciphertext }),
    }));
  }

  async function listMessages() {
    return handle(await fetch("/messages", {
      method: "GET",
      headers: headers(false),
    }));
  }

  async function downloadMessage(id) {
    return handle(await fetch("/messages/" + encodeURIComponent(id) + "/download", {
      method: "GET",
      headers: headers(false),
    }));
  }

  async function forwardMessage(id, to, encField, ciphertext) {
    return handle(await fetch("/messages/" + encodeURIComponent(id) + "/forward", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({ to, enc: encField, ciphertext }),
    }));
  }

  async function deleteMessage(id) {
    return handle(await fetch("/messages/" + encodeURIComponent(id), {
      method: "DELETE",
      headers: headers(false),
    }));
  }

  async function revokeShare(id, uid) {
    return handle(await fetch("/messages/" + encodeURIComponent(id) + "/share/" + encodeURIComponent(uid), {
      method: "DELETE",
      headers: headers(false),
    }));
  }

  async function health() {
    return handle(await fetch("/health", { method: "GET" }));
  }

  window.RizzAPI = {
    setToken, getToken, userIdFromToken,
    register, login, changePassword,
    updatePublicKey, getPublicKey,
    sendMessage, listMessages, downloadMessage, forwardMessage, deleteMessage, revokeShare,
    health,
  };
})();
