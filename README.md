# Trivectra

All-in-one privacy suite (no npm dependencies; Node 18+). Run `npm start` then open http://localhost:3000.

1. **Audit** - hashes an email/handle in-browser (SHA-256), queries mock registries, computes a 0-100 privacy score with removal steps.
2. **Vault** - AES-256-GCM chunked encryption via Web Crypto before upload. Link: `/?v=<id>#key=<key>`; the key stays in the URL fragment and is never sent to the server. Chunks are bound with AAD (index/total) to detect tampering/truncation. Links expire and can be burn-after-read.
3. **P2P** - WebRTC data channel with backpressure. The server only relays SDP/ICE for a 6-digit room; share the link `/?room=<code>`, the code or the QR. Multi-file queue, drag and drop, accept/decline, speed and ETA, and ack-based flow control. Receivers on Chrome/Edge stream straight to disk, so there is no size limit; other browsers buffer in memory. File bytes never touch the server.

Integration: save the audit report into the Vault; send a vault file via P2P. A public STUN server is used; strict NATs may need TURN.

Username scans check 1,844 live profile sources, split across eight serverless requests so each request stays within the function time limit. The collection includes 242 definitions from the MIT-licensed Sherlock project, filtered with `node tools/validate-sites.js <sherlock data.json>`; 171 sites from the CC BY-SA 4.0 [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) project, validated with `node tools/validate-wmn.js <wmn-data.json>`; and 1,431 live-validated sites from the MIT-licensed [Maigret](https://github.com/soxoj/maigret) project (`sites-maigret.json`), produced with `node tools/validate-maigret.js <maigret data.json>`. Maigret entries are retained only when the scanner recognizes a known account and rejects a nonexistent username. Instagram, Facebook, Reddit, Threads, LinkedIn and Spotify require login to check, so the report gives manual-check links instead of guessing.

## Deploying on Vercel

public/ is served statically and api/index.js (sharing lib/api.js with the local server.js) serves the API. Vercel functions are stateless, so the vault and P2P signaling use Redis:

1. Set `REDIS_URL` (any Redis, e.g. redis://default:password@host:port) in the Vercel project settings, or add the Upstash integration (or set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN; KV_REST_API_URL/KV_REST_API_TOKEN also work) in the Vercel project settings.
2. Deploy the branch that contains this code (merge it to your production branch, normally main).

Without those variables the app uses an in-memory store (fine locally, not on Vercel). On Vercel the vault is chunked (about 19 MB max, 512 KB parts), P2P signaling uses polling, and username scans stop after about 48 s (unchecked sites show as unknown). Rooms stay open for 1 hour. Some sites may block Vercel datacenter IPs more than home IPs.
