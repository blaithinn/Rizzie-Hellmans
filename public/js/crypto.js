/* =====================================================================
   RizzCrypto — browser replica of the C++ client's CryptoUtils.
   Scheme (must match src/cpp-client/src/CryptoUtils.cpp EXACTLY):

     keypair      : X25519  (libsodium crypto_box_keypair == TweetNaCl box)
     DH           : X25519(eph_sk, recipient_pk)  (crypto_scalarmult)
     KDF          : HKDF-SHA256, salt = 32 zero bytes (libsodium null salt),
                    info = "securechat-v1" || eph_pk  -> 32-byte AES key
     AEAD         : AES-256-GCM, random 12-byte nonce, 16-byte tag
     enc field    : base64( eph_pk )                      (32 bytes)
     ciphertext   : base64( nonce(12) || ciphertext+tag )

   Sender uses a FRESH ephemeral keypair per message and discards the
   secret — so a sender can NOT decrypt their own sent messages (just
   like the C++ client). The UI caches sent plaintext locally instead.
   ===================================================================== */
(function () {
  const KDF_INFO_PREFIX = "securechat-v1";
  const enc = new TextEncoder();

  function b64encode(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin); // standard base64 with padding (RFC 4648) — matches server BASE64_RE
  }

  function b64decode(str) {
    const bin = atob(str.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // ---- HKDF-SHA256 (split extract+expand done in one WebCrypto call) ----
  async function deriveAesKey(sharedSecret, ephPubKey) {
    const ikm = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
    const info = concatBytes(enc.encode(KDF_INFO_PREFIX), ephPubKey);
    const salt = new Uint8Array(32); // libsodium null-salt == 32 zero bytes (RFC 5869 §2.2)
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      ikm,
      256
    );
    return new Uint8Array(bits);
  }

  // ---- key pair generation (X25519) ----
  function generateKeyPair() {
    const kp = nacl.box.keyPair(); // Curve25519 / X25519, identical to crypto_box_keypair
    return { publicKey: b64encode(kp.publicKey), secretKey: b64encode(kp.secretKey) };
  }

  // ---- encrypt a plaintext string for a recipient public key (base64) ----
  async function encryptMessage(plaintext, recipientPublicKeyB64) {
    const recipientPk = b64decode(recipientPublicKeyB64);
    if (recipientPk.length !== 32) throw new Error("recipient public key must be 32 bytes");

    // Step 1: ephemeral X25519 keypair (discard secret after use)
    const eph = nacl.box.keyPair();
    const ephPk = eph.publicKey;       // == encOut
    const ephSk = eph.secretKey;

    // Step 2: X25519 DH
    const shared = nacl.scalarMult(ephSk, recipientPk);
    nacl.lowlevel ? null : null;
    eph.secretKey.fill(0); // best-effort wipe

    // Step 3: HKDF
    const aesKeyBytes = await deriveAesKey(shared, ephPk);
    shared.fill(0);

    // Step 4: AES-256-GCM
    const aesKey = await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["encrypt"]);
    aesKeyBytes.fill(0);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      aesKey,
      enc.encode(plaintext)
    );
    const payload = concatBytes(nonce, new Uint8Array(ctBuf)); // nonce || ciphertext+tag

    return { enc: b64encode(ephPk), ciphertext: b64encode(payload) };
  }

  // ---- decrypt (recipient side) ----
  async function decryptMessage(encB64, ciphertextB64, mySecretKeyB64) {
    const ephPk = b64decode(encB64);
    const payload = b64decode(ciphertextB64);
    const mySk = b64decode(mySecretKeyB64);
    if (ephPk.length !== 32) throw new Error("enc (eph pubkey) must be 32 bytes");
    if (payload.length < 12 + 16) throw new Error("payload too short");

    const shared = nacl.scalarMult(mySk, ephPk); // X25519 is commutative
    const aesKeyBytes = await deriveAesKey(shared, ephPk);
    shared.fill(0);

    const aesKey = await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["decrypt"]);
    aesKeyBytes.fill(0);
    const nonce = payload.slice(0, 12);
    const ct = payload.slice(12);
    const ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      aesKey,
      ct
    );
    return new TextDecoder().decode(ptBuf);
  }

  window.RizzCrypto = {
    generateKeyPair,
    encryptMessage,
    decryptMessage,
    b64encode,
    b64decode,
  };
})();
