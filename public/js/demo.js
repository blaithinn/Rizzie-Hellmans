/* =====================================================================
   RizzDemo — OFFLINE PREVIEW ONLY. Activated solely by ?demo=1 (or
   localStorage rizz_demo="1"). It monkeypatches window.fetch with an
   in-memory mock that mirrors the real backend's routes & responses, so
   the UI can be previewed without running the Node server.

   It changes NO backend logic — in production (no ?demo flag) this file
   is inert and every request hits the real server. Real X25519/AES-GCM
   crypto round-trips through the mock via seeded keypairs + a reply bot.
   ===================================================================== */
(function () {
  const params = new URLSearchParams(location.search);
  const ACTIVE = params.get("demo") === "1" || localStorage.getItem("rizz_demo") === "1";
  if (!ACTIVE) return;
  if (params.get("demo") === "1") localStorage.setItem("rizz_demo", "1");

  const ME = { id: 1, username: "rizzlord", password: "rizzword1" };
  const users = [];      // {id, username, password, publicKey, secretKey}
  const messages = [];   // {id, sender_id, recipient_id, enc, ciphertext, tx_hash, sent_at}
  const shares = [];     // {message_id, shared_with_user_id}
  let msgSeq = 0;

  const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  const fakeTx = () => "0x" + hex(32);

  function b64url(obj) {
    return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function tokenFor(id, username) {
    return b64url({ alg: "demo" }) + "." + b64url({ id, username, tokenVersion: 0 }) + ".demo";
  }
  function findUser(id) { return users.find((u) => u.id === Number(id)); }
  function findByName(n) { return users.find((u) => u.username === n); }

  async function mkUser(id, username, password) {
    const kp = window.RizzCrypto.generateKeyPair();
    const u = { id, username, password, publicKey: kp.publicKey, secretKey: kp.secretKey };
    users.push(u);
    return u;
  }

  async function botEncryptTo(recipient, text) {
    return window.RizzCrypto.encryptMessage(text, recipient.publicKey);
  }

  function storeMsg(from, to, enc, ct, when) {
    const m = {
      id: ++msgSeq, sender_id: from, recipient_id: to,
      enc, ciphertext: ct, tx_hash: fakeTx(),
      sent_at: when || new Date().toISOString(),
    };
    messages.push(m);
    return m;
  }

  const BOT_IDS = new Set();
  const BOT_LINES = [
    "are you a parking ticket? bc you've got FINE written all over you 💕",
    "is it hot in here or is that just your rizz coming through the phone 🔥",
    "delivered. received. CERTIFIED. you ate that text up fr 😩💘",
    "stop it you're making my little server heart race 🫠",
    "ngl that message just got stored on-chain forever. no take-backs 😘",
    "the rizzometer is OFF THE CHARTS rn 📈🔥",
  ];

  async function seed() {
    const me = await mkUser(ME.id, ME.username, ME.password);
    // expose my keypair to the app the same way the app stores it
    localStorage.setItem("rizz_key_" + ME.username, JSON.stringify({ pk: me.publicKey, sk: me.secretKey }));

    const cupid = await mkUser(7, "Cupid", "x");
    const sparkle = await mkUser(4, "DJ_Sparkle", "x");
    const banksy = await mkUser(12, "Bonita_Bae", "x");
    await mkUser(3, "Tinder_Tim", "x");     // discoverable, no history yet
    await mkUser(9, "CrushClara", "x");      // discoverable, no history yet
    [cupid.id, sparkle.id, banksy.id, 3, 9].forEach((id) => BOT_IDS.add(id));

    const sentCache = {};
    const t = (minsAgo) => new Date(Date.now() - minsAgo * 60000).toISOString();

    // --- Cupid thread ---
    let e;
    e = await botEncryptTo(me, "heyyy 👀 saw your public key from across the blockchain");
    storeMsg(cupid.id, me.id, e.enc, e.ciphertext, t(180));
    // a sent msg from me -> cupid (I can't decrypt my own; cache plaintext for display)
    e = await botEncryptTo(cupid, "oh? and what did my public key say to you 😏");
    { const m = storeMsg(me.id, cupid.id, e.enc, e.ciphertext, t(176)); sentCache[m.id] = "oh? and what did my public key say to you 😏"; }
    e = await botEncryptTo(me, "it said: 'this one's got that end-to-end encrypted rizz' 🔐💘");
    storeMsg(cupid.id, me.id, e.enc, e.ciphertext, t(174));
    e = await botEncryptTo(cupid, "you had me at AES-256-GCM 🥵");
    { const m = storeMsg(me.id, cupid.id, e.enc, e.ciphertext, t(170)); sentCache[m.id] = "you had me at AES-256-GCM 🥵"; }

    // --- DJ_Sparkle ---
    e = await botEncryptTo(me, "yo the rizz at the function was UNREAL last night ✨🔥");
    storeMsg(sparkle.id, me.id, e.enc, e.ciphertext, t(60));

    // --- Bonita_Bae ---
    e = await botEncryptTo(me, "did you really store our convo on Sepolia 😭 that's so romantic");
    storeMsg(banksy.id, me.id, e.enc, e.ciphertext, t(15));

    localStorage.setItem("rizz_sent_" + ME.username, JSON.stringify(sentCache));
    localStorage.setItem("rizz_nicks_" + ME.username, JSON.stringify({ 7: "Cupid 💘", 4: "DJ Sparkle ✨", 12: "Bonita Bae 🔥" }));
  }

  // ----------------- routing -----------------
  function json(body, status) {
    return new Response(body == null ? "" : JSON.stringify(body), {
      status: status || 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  function authedId(init) {
    const h = (init && init.headers) || {};
    const auth = h["Authorization"] || h["authorization"] || "";
    if (!auth.startsWith("Bearer ")) return null;
    try {
      const p = auth.slice(7).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(p)).id;
    } catch (_) { return null; }
  }

  function scheduleBotReply(toBotId, fromMeId) {
    if (!BOT_IDS.has(Number(toBotId))) return;
    const bot = findUser(toBotId);
    const me = findUser(fromMeId);
    if (!bot || !me) return;
    setTimeout(async () => {
      const line = BOT_LINES[Math.floor(Math.random() * BOT_LINES.length)];
      const e = await botEncryptTo(me, line);
      storeMsg(bot.id, me.id, e.enc, e.ciphertext);
      window.dispatchEvent(new CustomEvent("rizz-demo-newmsg"));
    }, 1400 + Math.random() * 900);
  }

  const realFetch = window.fetch.bind(window);

  window.fetch = async function (input, init) {
    init = init || {};
    const url = typeof input === "string" ? input : input.url;
    let path;
    try { path = new URL(url, location.origin).pathname; } catch (_) { return realFetch(input, init); }
    if (!/^\/(auth|users|messages|health)\b/.test(path) && path !== "/verify") {
      return realFetch(input, init);
    }
    const method = (init.method || "GET").toUpperCase();
    let body = {};
    try { body = init.body ? JSON.parse(init.body) : {}; } catch (_) {}

    await ready;

    // health
    if (path === "/health") return json({ status: "ok" });

    // auth/register
    if (path === "/auth/register" && method === "POST") {
      if (findByName(body.username)) return json({ error: "Username already taken" }, 409);
      const id = users.length ? Math.max(...users.map((u) => u.id)) + 1 : 1;
      users.push({ id, username: body.username, password: body.password, publicKey: body.publicKey || null, secretKey: null });
      return json({ message: "User registered successfully" }, 201);
    }
    // auth/login
    if (path === "/auth/login" && method === "POST") {
      const u = findByName(body.username);
      if (!u || u.password !== body.password) return json({ error: "Invalid credentials" }, 401);
      return json({ token: tokenFor(u.id, u.username) });
    }
    // auth/password
    if (path === "/auth/password" && method === "PUT") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const u = findUser(id);
      if (!u || u.password !== body.currentPassword) return json({ error: "Current password is incorrect" }, 401);
      u.password = body.newPassword;
      return json({ message: "Password updated successfully" });
    }
    // users/pubkey (PUT)
    if (path === "/users/pubkey" && method === "PUT") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const u = findUser(id); if (u) u.publicKey = body.publicKey;
      return json({ message: "Public key updated" });
    }
    // users/:id/pubkey (GET)
    let m = path.match(/^\/users\/(\d+)\/pubkey$/);
    if (m && method === "GET") {
      if (!authedId(init)) return json({ error: "Missing or invalid authorization header" }, 401);
      const u = findUser(m[1]);
      if (!u) return json({ error: "User not found" }, 404);
      if (!u.publicKey) return json({ error: "User has not published a public key" }, 404);
      return json({ publicKey: u.publicKey });
    }
    // messages (POST)
    if (path === "/messages" && method === "POST") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      if (!findUser(body.to)) return json({ error: "Recipient not found" }, 404);
      const msg = storeMsg(id, Number(body.to), body.enc, body.ciphertext);
      scheduleBotReply(body.to, id);
      return json({ messageId: msg.id, txHash: msg.tx_hash }, 201);
    }
    // messages (GET)
    if (path === "/messages" && method === "GET") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const rows = messages.filter((x) => x.sender_id === id || x.recipient_id === id)
        .map((x) => ({ messageId: x.id, from: x.sender_id, to: x.recipient_id, enc: x.enc, ciphertext: x.ciphertext, txHash: x.tx_hash, sentAt: x.sent_at }));
      return json(rows);
    }
    // messages/:id/download
    m = path.match(/^\/messages\/(\d+)\/download$/);
    if (m && method === "GET") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const msg = messages.find((x) => x.id === Number(m[1]));
      if (!msg) return json({ error: "Message not found" }, 404);
      const ok = msg.sender_id === id || msg.recipient_id === id || shares.some((s) => s.message_id === msg.id && s.shared_with_user_id === id);
      if (!ok) return json({ error: "Access denied" }, 403);
      return json({ messageId: msg.id, from: msg.sender_id, enc: msg.enc, ciphertext: msg.ciphertext, txHash: msg.tx_hash, sentAt: msg.sent_at });
    }
    // messages/:id/forward
    m = path.match(/^\/messages\/(\d+)\/forward$/);
    if (m && method === "POST") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const orig = messages.find((x) => x.id === Number(m[1]));
      if (!orig) return json({ error: "Message not found" }, 404);
      const ok = orig.sender_id === id || orig.recipient_id === id || shares.some((s) => s.message_id === orig.id && s.shared_with_user_id === id);
      if (!ok) return json({ error: "Access denied" }, 403);
      if (!findUser(body.to)) return json({ error: "Recipient not found" }, 404);
      const msg = storeMsg(id, Number(body.to), body.enc, body.ciphertext);
      shares.push({ message_id: msg.id, shared_with_user_id: Number(body.to) });
      scheduleBotReply(body.to, id);
      return json({ messageId: msg.id, txHash: msg.tx_hash }, 201);
    }
    // messages/:id/share/:uid (DELETE)
    m = path.match(/^\/messages\/(\d+)\/share\/(\d+)$/);
    if (m && method === "DELETE") {
      const id = authedId(init); if (!id) return json({ error: "Invalid or expired token" }, 401);
      const msg = messages.find((x) => x.id === Number(m[1]));
      if (!msg) return json({ error: "Message not found" }, 404);
      if (msg.sender_id !== id) return json({ error: "Access denied" }, 403);
      if (!findUser(m[2])) return json({ error: "User not found" }, 404);
      const i = shares.findIndex((s) => s.message_id === Number(m[1]) && s.shared_with_user_id === Number(m[2]));
      if (i >= 0) shares.splice(i, 1);
      return json({ message: "Access revoked" });
    }

    return json({ error: "Not found (demo)" }, 404);
  };

  const ready = seed();
  window.__rizzDemoReady = ready;
  window.RizzDemo = { active: true, ME };
})();
