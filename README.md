# PrivacyShield

All-in-one privacy suite (no npm dependencies; Node 18+). Run `npm start` then open http://localhost:3000.

1. **Audit** - hashes an email/handle in-browser (SHA-256), queries mock registries, computes a 0-100 privacy score with removal steps.
2. **Vault** - AES-256-GCM chunked encryption via Web Crypto before upload. Link: `/?v=<id>#key=<key>`; the key stays in the URL fragment and is never sent to the server. Chunks are bound with AAD (index/total) to detect tampering/truncation. Links expire and can be burn-after-read.
3. **P2P** - WebRTC data channel with backpressure. The server only relays SDP/ICE for a 6-digit room (QR encodes `/?room=<code>`); file bytes never touch it.

Integration: save the audit report into the Vault; send a vault file via P2P. A public STUN server is used; strict NATs may need TURN.

Username scans also check ~240 sites (YouTube, TikTok, X, Twitch, Pinterest, Telegram, Snapchat, ...) via profile-URL checks. Site definitions come from the MIT-licensed Sherlock project and are filtered by `node tools/validate-sites.js <sherlock data.json>`, which keeps only sites that correctly distinguish an existing from a nonexistent user. Instagram, Facebook, Reddit, Threads, LinkedIn and Spotify require login to check, so the report gives manual-check links instead of guessing.
