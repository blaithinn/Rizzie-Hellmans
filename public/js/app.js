/* =====================================================================
   Rizz Me Through The Phone — app controller (vanilla JS).
   Talks to the real backend via RizzAPI; does real E2E crypto via
   RizzCrypto. No backend logic is modified — this is purely a frontend.
   ===================================================================== */
(function () {
  "use strict";

  const AVATARS = ["💘", "🔥", "😘", "💋", "✨", "💕", "😻", "🌹", "💌", "🫦"];
  const QUICK_EMOJI = ["💘", "🔥", "😘", "💋", "✨", "🥵", "🫦", "😩"];

  const state = {
    token: null,
    userId: null,
    username: null,
    keypair: null,          // {pk, sk}
    messages: [],           // decrypted/annotated
    contacts: [],           // [{id, last, lastAt, count}]
    activeId: null,
    pollTimer: null,
  };

  // ---------- tiny DOM helpers ----------
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  function avatarFor(id) { return AVATARS[Number(id) % AVATARS.length]; }

  function relTime(iso) {
    const d = new Date(iso), now = Date.now(), diff = (now - d.getTime()) / 1000;
    if (diff < 60) return "now";
    if (diff < 3600) return Math.floor(diff / 60) + "m";
    if (diff < 86400) return Math.floor(diff / 3600) + "h";
    if (diff < 604800) return Math.floor(diff / 86400) + "d";
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  function clockTime(iso) {
    return new Date(iso).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }
  function dayLabel(iso) {
    const d = new Date(iso), now = new Date();
    const same = (a, b) => a.toDateString() === b.toDateString();
    if (same(d, now)) return "Today";
    const y = new Date(now); y.setDate(now.getDate() - 1);
    if (same(d, y)) return "Yesterday";
    return d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
  }

  // ---------- localStorage (per-user) ----------
  const LS = {
    get token() { return localStorage.getItem("rizz_token"); },
    get username() { return localStorage.getItem("rizz_username"); },
    setSession(t, u) { localStorage.setItem("rizz_token", t); localStorage.setItem("rizz_username", u); },
    clearSession() { localStorage.removeItem("rizz_token"); localStorage.removeItem("rizz_username"); },
    keypair(u) { try { return JSON.parse(localStorage.getItem("rizz_key_" + u)); } catch (_) { return null; } },
    setKeypair(u, kp) { localStorage.setItem("rizz_key_" + u, JSON.stringify(kp)); },
    sent(u) { try { return JSON.parse(localStorage.getItem("rizz_sent_" + u)) || {}; } catch (_) { return {}; } },
    setSent(u, o) { localStorage.setItem("rizz_sent_" + u, JSON.stringify(o)); },
    nicks(u) { try { return JSON.parse(localStorage.getItem("rizz_nicks_" + u)) || {}; } catch (_) { return {}; } },
    setNicks(u, o) { localStorage.setItem("rizz_nicks_" + u, JSON.stringify(o)); },
    known(u) { try { return JSON.parse(localStorage.getItem("rizz_known_" + u)) || []; } catch (_) { return []; } },
    setKnown(u, a) { localStorage.setItem("rizz_known_" + u, JSON.stringify(a)); },
    shares(u) { try { return JSON.parse(localStorage.getItem("rizz_shares_" + u)) || {}; } catch (_) { return {}; } },
    setShares(u, o) { localStorage.setItem("rizz_shares_" + u, JSON.stringify(o)); },
  };

  function nickFor(id) {
    const nicks = LS.nicks(state.username);
    return nicks[id] || ("Rizzipient #" + id);
  }
  function setNick(id, name) {
    const nicks = LS.nicks(state.username);
    if (name && name.trim()) nicks[id] = name.trim(); else delete nicks[id];
    LS.setNicks(state.username, nicks);
  }

  // ---------- toast ----------
  function toast(msg, kind) {
    const wrap = $("#toastWrap");
    const t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.innerHTML = msg;
    wrap.appendChild(t);
    setTimeout(() => { t.style.transition = "opacity .3s, transform .3s"; t.style.opacity = "0"; t.style.transform = "translateY(10px)"; }, 2600);
    setTimeout(() => t.remove(), 2950);
  }

  // ---------- modal ----------
  function openModal(html) {
    closeModal();
    const veil = document.createElement("div");
    veil.className = "modal-veil";
    veil.id = "modalVeil";
    veil.innerHTML = '<div class="modal">' + html + "</div>";
    veil.addEventListener("mousedown", (e) => { if (e.target === veil) closeModal(); });
    document.getElementById("modalRoot").appendChild(veil);
    return veil;
  }
  function closeModal() { const v = $("#modalVeil"); if (v) v.remove(); }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

  // =====================================================================
  // AUTH
  // =====================================================================
  function setAuthMode(mode) {
    $$(".auth-tab").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
    $("#loginForm").classList.toggle("hidden", mode !== "login");
    $("#signupForm").classList.toggle("hidden", mode !== "signup");
    authMsg("");
  }
  function authMsg(text, kind) {
    const el = $("#authMsg");
    el.textContent = text || "";
    el.className = "auth-msg " + (kind || "");
  }

  async function doLogin(username, password) {
    authMsg("Sliding into the rizzosphere…");
    const data = await RizzAPI.login(username, password);
    const token = data.token;
    const uid = RizzAPI.userIdFromToken(token);
    let kp = LS.keypair(username);
    if (!kp) {
      // No local key on this device: generate one and publish it so future
      // messages can be decrypted. (Old messages stay locked — expected E2E.)
      const fresh = RizzCrypto.generateKeyPair();
      kp = { pk: fresh.publicKey, sk: fresh.secretKey };
      LS.setKeypair(username, kp);
      RizzAPI.setToken(token);
      try { await RizzAPI.updatePublicKey(kp.pk); } catch (_) {}
    }
    finishLogin(token, uid, username, kp);
  }

  async function doSignup(username, password) {
    authMsg("Generating your secret rizz keys…");
    const kp = RizzCrypto.generateKeyPair();
    await RizzAPI.register(username, password, kp.publicKey);
    LS.setKeypair(username, { pk: kp.publicKey, sk: kp.secretKey });
    authMsg("Account created! Logging you in…", "ok");
    const data = await RizzAPI.login(username, password);
    const uid = RizzAPI.userIdFromToken(data.token);
    finishLogin(data.token, uid, username, { pk: kp.publicKey, sk: kp.secretKey });
  }

  function finishLogin(token, uid, username, kp) {
    state.token = token; state.userId = uid; state.username = username; state.keypair = kp;
    RizzAPI.setToken(token);
    LS.setSession(token, username);
    showApp();
    loadMessages(true);
    startPolling();
  }

  function logout() {
    stopPolling();
    LS.clearSession();
    state.token = state.userId = state.username = state.keypair = null;
    state.messages = []; state.contacts = []; state.activeId = null;
    RizzAPI.setToken(null);
    showAuth();
  }

  // =====================================================================
  // SCREENS
  // =====================================================================
  function showAuth() {
    $("#authScreen").classList.remove("hidden");
    $("#appScreen").classList.add("hidden");
  }
  function showApp() {
    $("#authScreen").classList.add("hidden");
    $("#appScreen").classList.remove("hidden");
    $("#tbWho").textContent = state.username;
    $("#tbUid").textContent = "ID " + state.userId;
  }

  // =====================================================================
  // MESSAGES
  // =====================================================================
  async function loadMessages(showSpin) {
    if (!state.token) return;
    let raw;
    try { raw = await RizzAPI.listMessages(); }
    catch (e) {
      if (e.status === 401) { toast("💔 Session expired — log in again", "bad"); logout(); return; }
      if (showSpin) toast("Couldn't reach the rizzosphere 💔", "bad");
      return;
    }
    const sent = LS.sent(state.username);
    const out = await Promise.all(raw.map(async (m) => {
      const mine = m.from === state.userId;
      let plaintext = null, locked = false;
      if (mine) {
        plaintext = sent[m.messageId] != null ? sent[m.messageId] : null;
        locked = plaintext == null;
      } else {
        try { plaintext = await RizzCrypto.decryptMessage(m.enc, m.ciphertext, state.keypair.sk); }
        catch (_) { locked = true; }
      }
      return {
        id: m.messageId, from: m.from, to: m.to, enc: m.enc, ciphertext: m.ciphertext,
        txHash: m.txHash, sentAt: m.sentAt, mine, plaintext, locked,
      };
    }));
    out.sort((a, b) => new Date(a.sentAt) - new Date(b.sentAt));
    state.messages = out;
    buildContacts();
    renderSidebar();
    if (state.activeId != null) renderChat(state.activeId, true);
    else renderEmptyChat();
  }

  function buildContacts() {
    const map = new Map();
    for (const m of state.messages) {
      const other = m.mine ? m.to : m.from;
      if (other === state.userId) continue;
      const prev = map.get(other);
      if (!prev || new Date(m.sentAt) > new Date(prev.lastAt)) {
        map.set(other, { id: other, last: previewOf(m), lastAt: m.sentAt, count: (prev ? prev.count : 0) + 1 });
      } else {
        prev.count++;
      }
    }
    // include known contacts with no messages yet
    for (const id of LS.known(state.username)) {
      if (!map.has(id) && id !== state.userId) map.set(id, { id, last: "Start rizzing 💘", lastAt: null, count: 0 });
    }
    state.contacts = Array.from(map.values()).sort((a, b) => {
      if (!a.lastAt) return 1; if (!b.lastAt) return -1;
      return new Date(b.lastAt) - new Date(a.lastAt);
    });
  }

  function previewOf(m) {
    if (m.locked) return m.mine ? "🔒 Sent privately" : "🔒 Encrypted rizz";
    return (m.mine ? "You: " : "") + m.plaintext;
  }

  // =====================================================================
  // SIDEBAR
  // =====================================================================
  function renderSidebar() {
    const list = $("#rizzList");
    const q = ($("#searchBox").value || "").toLowerCase();
    const items = state.contacts.filter((c) =>
      nickFor(c.id).toLowerCase().includes(q) || String(c.id).includes(q));

    if (!items.length) {
      list.innerHTML = '<div class="list-empty"><div class="big">💌</div>' +
        '<p>' + (q ? "No rizzipients match that." : "No rizzipients yet.<br>Hit “＋ New Rizz” to shoot your shot.") + "</p></div>";
      return;
    }
    list.innerHTML = items.map((c) => {
      const active = c.id === state.activeId ? " active" : "";
      return '<div class="contact' + active + '" data-id="' + c.id + '">' +
        '<div class="c-avatar">' + avatarFor(c.id) + "</div>" +
        '<div class="c-body"><div class="c-top">' +
        '<span class="c-name">' + esc(nickFor(c.id)) + "</span>" +
        '<span class="c-meta">' + (c.lastAt ? relTime(c.lastAt) : "") + "</span></div>" +
        '<div class="c-last">' + esc(c.last) + "</div></div></div>";
    }).join("");
    $$(".contact", list).forEach((el) =>
      el.addEventListener("click", () => selectContact(Number(el.dataset.id))));
  }

  function selectContact(id) {
    state.activeId = id;
    renderSidebar();
    renderChat(id);
    if (window.matchMedia("(max-width:720px)").matches) {
      $(".sidebar").classList.add("tucked");
      $("#backBtn").classList.remove("hidden");
    }
  }

  // =====================================================================
  // CHAT
  // =====================================================================
  function renderEmptyChat() {
    $("#chatPane").innerHTML =
      '<div class="chat-empty"><div class="ce-inner">' +
      '<div class="ce-emoji">💘📱💘</div>' +
      "<h2>Rizz Me Through The Phone</h2>" +
      "<p>End-to-end encrypted DMs with that certified on-chain rizz. " +
      "Pick a Potential Rizzipient on the left, or start a brand-new rizz.</p>" +
      '<div style="margin-top:18px"><button class="rizz-btn" id="emptyNewBtn">＋ New Rizz</button></div>' +
      "</div></div>";
    const b = $("#emptyNewBtn"); if (b) b.addEventListener("click", openNewRizz);
  }

  function threadFor(id) {
    return state.messages.filter((m) => (m.mine ? m.to : m.from) === id);
  }

  function renderChat(id, keepScroll) {
    const pane = $("#chatPane");
    const msgs = threadFor(id);
    const prevScroll = keepScroll && $("#thread") ? $("#thread").scrollTop : null;
    const atBottom = keepScroll && $("#thread")
      ? ($("#thread").scrollHeight - $("#thread").scrollTop - $("#thread").clientHeight < 60) : true;

    pane.innerHTML =
      '<div class="chat-head">' +
        '<div class="c-avatar">' + avatarFor(id) + "</div>" +
        "<div><div class=\"ch-name\">" + esc(nickFor(id)) + "</div>" +
        '<div class="ch-sub"><span class="dot">●</span> Rizzipient ID ' + id + " · end-to-end encrypted</div></div>" +
        '<div style="flex:1"></div>' +
        '<button class="icon-btn" id="renameBtn" title="Rename rizzipient">✏️</button>' +
      "</div>" +
      '<div class="thread" id="thread">' + renderBubbles(msgs) + "</div>" +
      '<div class="composer">' +
        '<div class="emoji-pick">' + QUICK_EMOJI.map((e) => "<button data-e=\"" + e + "\">" + e + "</button>").join("") + "</div>" +
        '<textarea id="msgInput" rows="1" placeholder="Type your rizz…" maxlength="4000"></textarea>' +
        '<button class="send-btn" id="sendBtn" title="Send rizz">➤</button>' +
      "</div>";

    const thread = $("#thread");
    if (prevScroll != null && !atBottom) thread.scrollTop = prevScroll;
    else thread.scrollTop = thread.scrollHeight;

    $("#renameBtn").addEventListener("click", () => openRename(id));
    $("#sendBtn").addEventListener("click", sendCurrent);
    const ta = $("#msgInput");
    ta.addEventListener("input", () => { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 120) + "px"; });
    ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendCurrent(); } });
    $$(".emoji-pick button", pane).forEach((b) =>
      b.addEventListener("click", () => { ta.value += b.dataset.e; ta.focus(); ta.dispatchEvent(new Event("input")); }));
    bindBubbleActions();
    ta.focus();
  }

  function renderBubbles(msgs) {
    if (!msgs.length) {
      return '<div style="margin:auto;text-align:center;color:var(--rizz-ink-soft);font-weight:700">' +
        '<div style="font-size:2.6rem">🌹</div><p style="margin-top:8px">No rizz yet — send the first one!</p></div>';
    }
    let html = "", lastDay = "";
    for (const m of msgs) {
      const day = dayLabel(m.sentAt);
      if (day !== lastDay) { html += '<div class="day-sep">' + day + "</div>"; lastDay = day; }
      html += bubbleHtml(m);
    }
    return html;
  }

  function bubbleHtml(m) {
    const side = m.mine ? "out" : "in";
    let inner;
    if (m.locked) {
      inner = '<span class="bubble-text">' + (m.mine
        ? "🔒 Sent privately — content isn’t stored on this device"
        : "🔒 Couldn’t decrypt — this rizz was sealed for another key") + "</span>";
    } else {
      inner = '<span class="bubble-text">' + esc(m.plaintext).replace(/\n/g, "<br>") + "</span>";
    }

    let receipt = '<span title="' + esc(m.sentAt) + '">' + clockTime(m.sentAt) + "</span>";
    if (m.mine) {
      receipt += m.txHash
        ? ' <span class="rizz-receipt certified" data-tx="' + esc(m.txHash) + '"><span class="ticks">✓✓</span> Delivered Rizz</span>'
        : ' <span class="ticks">✓</span> Sent';
    } else if (m.txHash) {
      receipt += ' <span class="rizz-receipt" data-tx="' + esc(m.txHash) + '">🔗 verify</span>';
    }

    const acts = [];
    if (!m.locked) acts.push('<button class="mini-act" data-act="forward" data-id="' + m.id + '">↪ Forward</button>');
    acts.push('<button class="mini-act" data-act="download" data-id="' + m.id + '">⬇ Download</button>');
    if (m.txHash) acts.push('<button class="mini-act" data-act="certify" data-tx="' + esc(m.txHash) + '">🔥 Certify Rizz</button>');
    if (isSharedByMe(m.id)) acts.push('<button class="mini-act" data-act="manage" data-id="' + m.id + '">🔗 Access</button>');
    if (m.mine) acts.push('<button class="mini-act danger" data-act="delete" data-id="' + m.id + '">🗑 Delete</button>');

    return '<div class="bubble-row ' + side + '">' +
      '<div class="bubble' + (m.locked ? " locked" : "") + '">' + inner +
      '<div class="meta">' + receipt + "</div></div>" +
      '<div class="bubble-actions">' + acts.join("") + "</div></div>";
  }

  function bindBubbleActions() {
    $$(".rizz-receipt").forEach((el) =>
      el.addEventListener("click", () => openVerify(el.dataset.tx)));
    $$(".mini-act").forEach((el) => el.addEventListener("click", () => {
      const act = el.dataset.act;
      if (act === "forward") openForward(Number(el.dataset.id));
      else if (act === "download") downloadMsg(Number(el.dataset.id));
      else if (act === "certify") openVerify(el.dataset.tx);
      else if (act === "manage") openManageAccess(Number(el.dataset.id));
      else if (act === "delete") deleteMsg(Number(el.dataset.id));
    }));
  }

  // ---------- send ----------
  async function sendCurrent() {
    const ta = $("#msgInput");
    const text = (ta.value || "").trim();
    if (!text || state.activeId == null) return;
    const btn = $("#sendBtn");
    btn.disabled = true;
    try {
      const keyResp = await RizzAPI.getPublicKey(state.activeId);
      const { enc, ciphertext } = await RizzCrypto.encryptMessage(text, keyResp.publicKey);
      const res = await RizzAPI.sendMessage(state.activeId, enc, ciphertext);
      // cache plaintext locally so our own bubble is readable
      const sent = LS.sent(state.username);
      sent[res.messageId] = text;
      LS.setSent(state.username, sent);
      ta.value = ""; ta.style.height = "auto";
      await loadMessages();
      toast("Rizz delivered 💘 " + (res.txHash ? "Certified on-chain 🔗" : ""), "good");
    } catch (e) {
      if (e.status === 404) toast("That rizzipient hasn’t published a key 💔", "bad");
      else if (e.status === 401) { toast("Session expired 💔", "bad"); logout(); }
      else toast("Couldn’t send rizz: " + esc(e.message), "bad");
    } finally {
      btn.disabled = false;
    }
  }

  // =====================================================================
  // NEW RIZZ
  // =====================================================================
  function openNewRizz() {
    openModal(
      '<div class="modal-head"><h3>＋ Shoot Your Shot</h3><p>Start a new rizz with a Potential Rizzipient</p>' +
      '<button class="icon-btn modal-close" data-close>✕</button></div>' +
      '<div class="modal-body"><div class="modal-msg" id="nrMsg"></div>' +
      '<div class="rizz-field"><label>Rizzipient User ID</label>' +
      '<input class="rizz-input mono" id="nrId" placeholder="e.g. 7" inputmode="numeric"></div>' +
      '<div class="rizz-field"><label>Nickname (just for you)</label>' +
      '<input class="rizz-input" id="nrNick" placeholder="e.g. Cutie From Chem Class"></div>' +
      '<div class="modal-foot"><button class="rizz-btn ghost sm" data-close>Cancel</button>' +
      '<button class="rizz-btn sm" id="nrGo">Find &amp; Rizz 💘</button></div></div>');
    wireClose();
    $("#nrGo").addEventListener("click", async () => {
      const id = parseInt($("#nrId").value, 10);
      const nick = $("#nrNick").value;
      const msg = $("#nrMsg");
      if (!Number.isInteger(id) || id <= 0) { msg.textContent = "Enter a valid user ID."; msg.className = "modal-msg err"; return; }
      if (id === state.userId) { msg.textContent = "You can’t rizz yourself (self-love is valid though 💅)."; msg.className = "modal-msg err"; return; }
      msg.textContent = "Checking the rizzosphere…"; msg.className = "modal-msg";
      try {
        await RizzAPI.getPublicKey(id);
        if (nick.trim()) setNick(id, nick);
        const known = LS.known(state.username);
        if (!known.includes(id)) { known.push(id); LS.setKnown(state.username, known); }
        closeModal();
        buildContacts(); renderSidebar(); selectContact(id);
      } catch (e) {
        msg.className = "modal-msg err";
        msg.textContent = e.status === 404 ? "No rizzipient with that ID has published a key 💔" : "Lookup failed: " + e.message;
      }
    });
    setTimeout(() => $("#nrId").focus(), 50);
  }

  // =====================================================================
  // FORWARD
  // =====================================================================
  function openForward(msgId) {
    const m = state.messages.find((x) => x.id === msgId);
    if (!m || m.locked) { toast("Can’t forward sealed rizz 🔒", "bad"); return; }
    openModal(
      '<div class="modal-head"><h3>↪ Forward Rizz</h3><p>Re-encrypt &amp; pass this rizz along</p>' +
      '<button class="icon-btn modal-close" data-close>✕</button></div>' +
      '<div class="modal-body"><div class="modal-msg" id="fwMsg"></div>' +
      '<div class="kv">' + esc(m.plaintext) + "</div>" +
      '<div class="rizz-field" style="margin-top:16px"><label>Forward to Rizzipient ID</label>' +
      '<input class="rizz-input mono" id="fwId" placeholder="e.g. 12" inputmode="numeric"></div>' +
      '<div class="modal-foot"><button class="rizz-btn ghost sm" data-close>Cancel</button>' +
      '<button class="rizz-btn sm" id="fwGo">Forward 💌</button></div></div>');
    wireClose();
    $("#fwGo").addEventListener("click", async () => {
      const to = parseInt($("#fwId").value, 10);
      const msg = $("#fwMsg");
      if (!Number.isInteger(to) || to <= 0) { msg.textContent = "Enter a valid user ID."; msg.className = "modal-msg err"; return; }
      msg.textContent = "Re-encrypting for the new rizzipient…"; msg.className = "modal-msg";
      try {
        const keyResp = await RizzAPI.getPublicKey(to);
        const { enc, ciphertext } = await RizzCrypto.encryptMessage(m.plaintext, keyResp.publicKey);
        const res = await RizzAPI.forwardMessage(m.id, to, enc, ciphertext);
        // cache plaintext for the new (forwarded) message + record the share
        const sent = LS.sent(state.username); sent[res.messageId] = m.plaintext; LS.setSent(state.username, sent);
        const sh = LS.shares(state.username); sh[res.messageId] = [to]; LS.setShares(state.username, sh);
        closeModal();
        await loadMessages();
        toast("Rizz forwarded 💌 Certified on-chain 🔗", "good");
      } catch (e) {
        msg.className = "modal-msg err";
        msg.textContent = e.status === 404 ? "That rizzipient hasn’t published a key 💔" : "Forward failed: " + e.message;
      }
    });
    setTimeout(() => $("#fwId").focus(), 50);
  }

  // =====================================================================
  // DOWNLOAD
  // =====================================================================
  async function downloadMsg(msgId) {
    try {
      const data = await RizzAPI.downloadMessage(msgId);
      let plaintext = "🔒 (encrypted — not decryptable on this device)";
      const mine = data.from === state.userId;
      if (mine) {
        const sent = LS.sent(state.username);
        plaintext = sent[msgId] != null ? sent[msgId] : plaintext;
      } else {
        try { plaintext = await RizzCrypto.decryptMessage(data.enc, data.ciphertext, state.keypair.sk); } catch (_) {}
      }
      const out = [
        "💘 Rizz Me Through The Phone — message export",
        "──────────────────────────────────────────",
        "Message ID : " + data.messageId,
        "From ID    : " + data.from,
        "Sent At    : " + data.sentAt,
        "Tx Hash    : " + (data.txHash || "(none)"),
        "Verify at  : /verify?tx=" + (data.txHash || ""),
        "",
        "Decrypted rizz:",
        plaintext,
        "",
        "── encrypted blobs ──",
        "enc        : " + data.enc,
        "ciphertext : " + data.ciphertext,
      ].join("\n");
      const blob = new Blob([out], { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "rizz-message-" + data.messageId + ".txt";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      toast("Rizz downloaded ⬇️", "good");
    } catch (e) {
      toast(e.status === 403 ? "Access denied 💔" : "Download failed 💔", "bad");
    }
  }

  // =====================================================================
  // DELETE MESSAGE
  // =====================================================================
  async function deleteMsg(msgId) {
    if (!confirm("Delete this message? This cannot be undone.")) return;
    try {
      await RizzAPI.deleteMessage(msgId);
      state.messages = state.messages.filter((m) => m.id !== msgId);
      const sent = LS.sent(state.username);
      delete sent[msgId];
      LS.setSent(state.username, sent);
      toast("Message deleted 🗑", "good");
      renderChat(state.activeId, true);
    } catch (e) {
      toast(e.status === 403 ? "Access denied 💔" : "Delete failed 💔", "bad");
    }
  }

  // =====================================================================
  // MANAGE ACCESS / REVOKE SHARE
  // =====================================================================
  function isSharedByMe(msgId) {
    const sh = LS.shares(state.username);
    return sh[msgId] && sh[msgId].length;
  }
  function openManageAccess(msgId) {
    const sh = LS.shares(state.username);
    const list = sh[msgId] || [];
    const rows = list.length
      ? list.map((uid) => '<div class="share-row"><span>' + esc(nickFor(uid)) + ' <span style="opacity:.6;font-family:var(--font-mono)">#' + uid + "</span></span>" +
          '<button class="rizz-btn ghost sm" data-revoke="' + uid + '">Revoke</button></div>').join("")
      : '<p style="color:var(--rizz-ink-soft);font-weight:700">No active shares.</p>';
    openModal(
      '<div class="modal-head"><h3>🔗 Rizz Access</h3><p>Who can see this forwarded rizz</p>' +
      '<button class="icon-btn modal-close" data-close>✕</button></div>' +
      '<div class="modal-body"><div class="modal-msg" id="maMsg"></div>' + rows +
      '<div class="modal-foot"><button class="rizz-btn sm" data-close>Done</button></div></div>');
    wireClose();
    $$("[data-revoke]").forEach((b) => b.addEventListener("click", async () => {
      const uid = Number(b.dataset.revoke);
      try {
        await RizzAPI.revokeShare(msgId, uid);
        const s = LS.shares(state.username);
        s[msgId] = (s[msgId] || []).filter((x) => x !== uid);
        if (!s[msgId].length) delete s[msgId];
        LS.setShares(state.username, s);
        toast("Access revoked 🔒", "good");
        closeModal(); openManageAccess(msgId); renderChat(state.activeId, true);
      } catch (e) {
        const mm = $("#maMsg"); mm.className = "modal-msg err"; mm.textContent = "Revoke failed: " + e.message;
      }
    }));
  }

  // =====================================================================
  // RENAME
  // =====================================================================
  function openRename(id) {
    openModal(
      '<div class="modal-head"><h3>✏️ Rename Rizzipient</h3><p>A private nickname, just for you</p>' +
      '<button class="icon-btn modal-close" data-close>✕</button></div>' +
      '<div class="modal-body"><div class="rizz-field"><label>Nickname</label>' +
      '<input class="rizz-input" id="rnInput" value="' + esc(nickFor(id)) + '"></div>' +
      '<div class="modal-foot"><button class="rizz-btn ghost sm" data-close>Cancel</button>' +
      '<button class="rizz-btn sm" id="rnGo">Save</button></div></div>');
    wireClose();
    $("#rnGo").addEventListener("click", () => {
      setNick(id, $("#rnInput").value);
      closeModal(); buildContacts(); renderSidebar(); renderChat(id, true);
    });
    setTimeout(() => $("#rnInput").focus(), 50);
  }

  // =====================================================================
  // VERIFY (opens the certified-rizz page)
  // =====================================================================
  function openVerify(tx) {
    window.open("verify.html?tx=" + encodeURIComponent(tx || ""), "_blank");
  }

  // =====================================================================
  // SETTINGS
  // =====================================================================
  function openSettings() {
    const kp = state.keypair || {};
    openModal(
      '<div class="modal-head"><h3>⚙️ Rizz Settings</h3><p>@' + esc(state.username) + " · ID " + state.userId + "</p>" +
      '<button class="icon-btn modal-close" data-close>✕</button></div>' +
      '<div class="modal-body">' +
        '<div class="section-label">Your Rizz Identity</div>' +
        '<div class="rizz-field"><label>Share this ID so others can rizz you</label>' +
        '<div class="kv">User ID: ' + state.userId + "</div></div>" +
        '<div class="rizz-field"><label>Public Key</label><div class="kv" id="pkBox">' + esc(kp.pk || "(none)") + "</div></div>" +
        '<button class="rizz-btn ghost sm" id="copyPk">📋 Copy public key</button>' +

        '<div class="divider"></div>' +
        '<div class="section-label">Change Password</div>' +
        '<div class="modal-msg" id="pwMsg"></div>' +
        '<div class="rizz-field"><label>Current password</label><input type="password" class="rizz-input" id="pwCur"></div>' +
        '<div class="rizz-field"><label>New password (min 8)</label><input type="password" class="rizz-input" id="pwNew"></div>' +
        '<button class="rizz-btn sm" id="pwGo">Update password</button>' +

        '<div class="divider"></div>' +
        '<div class="section-label">Key Backup</div>' +
        '<p style="font-size:.8rem;color:var(--rizz-ink-soft);font-weight:700;margin-bottom:10px">Your secret key never leaves this device. Back it up to read your rizz on another device.</p>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
        '<button class="rizz-btn ghost sm" id="expKey">⬇ Export key</button>' +
        '<button class="rizz-btn ghost sm" id="impKey">⬆ Import key</button>' +
        '<a class="rizz-btn ghost sm" style="text-decoration:none" href="verify.html" target="_blank">🔥 Verify a rizz</a>' +
        "</div>" +

        '<div class="divider"></div>' +
        '<div class="modal-foot" style="justify-content:space-between">' +
        '<button class="rizz-btn ghost sm" id="logoutBtn">Log out</button>' +
        '<button class="rizz-btn sm" data-close>Done</button></div>' +
      "</div>");
    wireClose();

    $("#copyPk").addEventListener("click", () => {
      navigator.clipboard && navigator.clipboard.writeText(kp.pk || "");
      toast("Public key copied 📋", "good");
    });
    $("#pwGo").addEventListener("click", async () => {
      const cur = $("#pwCur").value, nw = $("#pwNew").value, msg = $("#pwMsg");
      if (nw.length < 8) { msg.className = "modal-msg err"; msg.textContent = "New password must be at least 8 characters."; return; }
      msg.className = "modal-msg"; msg.textContent = "Updating…";
      try {
        await RizzAPI.changePassword(cur, nw);
        msg.className = "modal-msg ok"; msg.textContent = "Password updated! Logging you back in…";
        // server invalidates the session (token_version bump) — re-login
        setTimeout(async () => {
          try { const d = await RizzAPI.login(state.username, nw); state.token = d.token; RizzAPI.setToken(d.token); LS.setSession(d.token, state.username); toast("Password changed 🔐", "good"); closeModal(); }
          catch (_) { toast("Password changed — please log in again 🔐", "good"); closeModal(); logout(); }
        }, 700);
      } catch (e) {
        msg.className = "modal-msg err";
        msg.textContent = e.status === 401 ? "Current password is incorrect." : "Update failed: " + e.message;
      }
    });
    $("#expKey").addEventListener("click", () => {
      const blob = new Blob([JSON.stringify({ username: state.username, publicKey: kp.pk, secretKey: kp.sk }, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = "rizz-key-" + state.username + ".json";
      document.body.appendChild(a); a.click(); a.remove();
      toast("Key backed up ⬇️ keep it secret!", "good");
    });
    $("#impKey").addEventListener("click", () => {
      const inp = document.createElement("input"); inp.type = "file"; inp.accept = "application/json";
      inp.addEventListener("change", () => {
        const f = inp.files[0]; if (!f) return;
        const r = new FileReader();
        r.onload = () => {
          try {
            const data = JSON.parse(r.result);
            if (!data.publicKey || !data.secretKey) throw new Error("bad file");
            LS.setKeypair(state.username, { pk: data.publicKey, sk: data.secretKey });
            state.keypair = { pk: data.publicKey, sk: data.secretKey };
            toast("Key imported 🔑 reloading rizz…", "good");
            closeModal(); loadMessages(true);
          } catch (_) { toast("That doesn’t look like a rizz key 💔", "bad"); }
        };
        r.readAsText(f);
      });
      inp.click();
    });
    $("#logoutBtn").addEventListener("click", () => { closeModal(); logout(); });
  }

  function wireClose() { $$("[data-close]").forEach((b) => b.addEventListener("click", closeModal)); }

  // =====================================================================
  // POLLING
  // =====================================================================
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(() => loadMessages(false), 4000);
  }
  function stopPolling() { if (state.pollTimer) clearInterval(state.pollTimer); state.pollTimer = null; }
  window.addEventListener("rizz-demo-newmsg", () => loadMessages(false));

  // =====================================================================
  // BOOT
  // =====================================================================
  async function boot() {
    if (window.__rizzDemoReady) { try { await window.__rizzDemoReady; } catch (_) {} $("#demoBanner").classList.remove("hidden"); document.body.classList.add("demo"); }

    // auth wiring
    $$(".auth-tab").forEach((b) => b.addEventListener("click", () => setAuthMode(b.dataset.mode)));
    $("#loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const u = $("#loginUser").value.trim(), p = $("#loginPass").value;
      if (!u || !p) { authMsg("Enter your username and password.", "err"); return; }
      try { await doLogin(u, p); }
      catch (err) { authMsg(err.status === 401 ? "💔 Wrong username or password." : "💔 " + err.message, "err"); }
    });
    $("#signupForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const u = $("#suUser").value.trim(), p = $("#suPass").value, c = $("#suConfirm").value;
      if (u.length < 3) { authMsg("Username must be 3+ characters (letters, numbers, _).", "err"); return; }
      if (p.length < 8) { authMsg("Password must be at least 8 characters.", "err"); return; }
      if (p !== c) { authMsg("Passwords don’t match 💔", "err"); return; }
      try { await doSignup(u, p); }
      catch (err) { authMsg(err.status === 409 ? "💔 That username is already taken." : "💔 " + err.message, "err"); }
    });

    // topbar wiring
    $("#settingsBtn").addEventListener("click", openSettings);
    $("#newRizzBtn").addEventListener("click", openNewRizz);
    $("#searchBox").addEventListener("input", renderSidebar);
    $("#backBtn").addEventListener("click", () => {
      $(".sidebar").classList.remove("tucked");
      $("#backBtn").classList.add("hidden");
    });

    // floaties
    spawnFloaties();

    // resume session
    const t = LS.token, u = LS.username;
    if (t && u) {
      const kp = LS.keypair(u);
      const uid = RizzAPI.userIdFromToken(t);
      if (kp && uid) {
        state.token = t; state.username = u; state.userId = uid; state.keypair = kp;
        RizzAPI.setToken(t);
        // validate token still works; if not, fall back to auth
        try { await RizzAPI.listMessages(); showApp(); loadMessages(true); startPolling(); return; }
        catch (_) { LS.clearSession(); }
      }
    }
    // demo: prefill credentials for instant try
    if (window.RizzDemo && window.RizzDemo.active) {
      $("#loginUser").value = window.RizzDemo.ME.username;
      $("#loginPass").value = window.RizzDemo.ME.password;
    }
    setAuthMode("login");
    showAuth();
  }

  function spawnFloaties() {
    const wrap = $("#authScreen");
    const emojis = ["💘", "🔥", "💕", "✨", "💋", "🌹"];
    for (let i = 0; i < 9; i++) {
      const s = document.createElement("div");
      s.className = "floaty";
      s.textContent = emojis[i % emojis.length];
      s.style.left = Math.random() * 100 + "vw";
      s.style.fontSize = 1.2 + Math.random() * 1.8 + "rem";
      s.style.animationDuration = 9 + Math.random() * 10 + "s";
      s.style.animationDelay = -Math.random() * 12 + "s";
      wrap.appendChild(s);
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
