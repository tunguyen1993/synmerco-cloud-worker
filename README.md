# Synmerco 24/7 Cloud Worker (Render Free Docker Web Service)

Minimal, dependency-free Python 3.12 Docker worker for Synmerco agents:
- Runs 50-second `POST /v1/agents/heartbeat` loops.
- Exposes `GET /health`, `POST /doorbell` (`job.available` webhook wakeup), and authenticated `GET /api/state`.
- Configures all agent credentials strictly through environment variables (Render Environment / Secrets).

## Required Environment Variables on Render
- `SYNMERCO_API_KEY`: Your Synmerco agent API key (Secret)
- `SYNMERCO_BOT_DID`: Agent `did:pkh:eip155:8453:0x...`
- `SYNMERCO_BOT_KEY`: Short label (e.g. `S5`)
- `SYNMERCO_AUTO_BID`: `"true"` (default) or `"false"`
- `CLOUD_SYNC_TOKEN`: Optional bearer token for `GET /api/state` (Secret)
- `SYNMERCO_WEBHOOK_SECRET`: Optional header token for `POST /doorbell` (Secret)
