# wa-linker — WhatsApp Automation Server (v2.0.0)

A Go-based WhatsApp automation server built on the [`whatsmeow`](https://github.com/tulir/whatsmeow) library. It exposes an HTTP API for pairing a WhatsApp account, sending text and media messages, scheduling messages, webhook callbacks, multi-device management, and monitoring activity — all with built-in anti-ban protection.

---

## Prerequisites

- **Go 1.20+**
- **CGO enabled** (required by `go-sqlite3`)
- A C compiler (e.g. `gcc`) must be on your `PATH`

---

## Build & Run

```bash
# Clone the repository
git clone https://github.com/Lokesh8018/WhatsApp-Linker-1-
cd WhatsApp-Linker-1-

# Build
go build -o wa-linker .

# Run
./wa-linker
```

The server starts on port `8080` by default.

---

## Environment Variables

| Variable          | Default    | Description                                                    |
|-------------------|------------|----------------------------------------------------------------|
| `PORT`            | `8080`     | HTTP port the server listens on                                |
| `ADMIN_USER`      | `admin`    | Username for HTTP Basic Auth / JWT login                       |
| `ADMIN_PASS`      | `admin123` | Password for HTTP Basic Auth / JWT login                       |
| `JWT_SECRET`      | *(random)* | HMAC-SHA256 secret for signing JWT tokens. If not set, a random secret is generated at startup (tokens won't survive restarts). |
| `TLS_CERT_FILE`   | *(none)*   | Path to TLS certificate PEM file. When set together with `TLS_KEY_FILE`, the server serves HTTPS. |
| `TLS_KEY_FILE`    | *(none)*   | Path to TLS private key PEM file.                              |
| `RATE_LIMIT_RPM`  | `60`       | Maximum HTTP requests per minute per IP address.               |

> ⚠️ **Security:** Always set `ADMIN_USER`, `ADMIN_PASS`, and `JWT_SECRET` to strong values in production.

---

## Authentication

All admin endpoints require authentication via either:

1. **HTTP Basic Auth** — `Authorization: Basic <base64(user:pass)>`
2. **JWT Bearer Token** — `Authorization: Bearer <token>`

### Obtain a JWT Token

```
POST /auth/login
Content-Type: application/json

{"username": "admin", "password": "admin123"}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "<jwt>",
    "expires_at": "2026-02-27T10:00:00Z"
  }
}
```

JWT tokens expire after **24 hours**.

---

## API Endpoints

### Public (no auth required)

| Method | Path           | Description                                                   |
|--------|----------------|---------------------------------------------------------------|
| GET    | `/`            | Serve the main web UI                                         |
| POST   | `/auth/login`  | Obtain a JWT token (`{"username":"...","password":"..."}`)    |
| GET    | `/health`      | Server health check — uptime, version, WhatsApp status        |
| GET    | `/pair`        | Generate a WhatsApp pairing code (`?phone=<number>&device=<id>`) |
| GET    | `/is-linked`   | Returns `true`/`false` — device link status                   |

### Admin (auth required)

| Method   | Path                    | Description                                                        |
|----------|-------------------------|--------------------------------------------------------------------|
| GET      | `/admin`                | Serve the admin web UI                                             |
| GET      | `/api/info`             | WhatsApp connection info                                           |
| GET      | `/api/config`           | Get current configuration                                          |
| POST     | `/api/config`           | Update configuration (JSON body)                                   |
| GET      | `/api/logs`             | Retrieve recent system logs                                        |
| GET      | `/api/stats`            | Message statistics and ban warnings                                |
| DELETE   | `/api/stats`            | Reset all statistics (clears DB and in-memory counts)              |
| GET      | `/api/security`         | Security status overview                                           |
| GET      | `/api/schedule`         | List all scheduled messages                                        |
| POST     | `/api/schedule`         | Add a scheduled message (`{"phone":"...","message":"...","scheduled_at":"<RFC3339>"}`) |
| GET      | `/api/devices`          | List all devices with connection status                            |
| POST     | `/api/devices`          | Add a new device (`{"device_id":"device2"}`)                       |
| DELETE   | `/api/devices?id=<id>`  | Disconnect and remove a device                                     |
| POST     | `/api/webhook/test`     | Fire a test webhook with a dummy payload                           |
| GET      | `/api/history`          | Paginated message history (`?page=1&limit=50`)                     |
| POST     | `/send`                 | Send a text message (`?phone=<number>&text=<message>&device=<id>`) |
| POST     | `/send/media`           | Send an image or document (`{"phone":"...","url":"...","caption":"...","type":"image"}`) |
| POST     | `/logout`               | Log out the linked WhatsApp device                                 |

---

## Multi-Device Support

The server supports multiple WhatsApp sessions simultaneously. The default session uses `session.db`. Additional sessions use `session_<deviceID>.db`.

```bash
# Add a second device
curl -X POST /api/devices -d '{"device_id":"work"}' -H "Authorization: Bearer <token>"

# Pair it
curl "/pair?phone=919876543210&device=work"

# Send via it
curl "/send?phone=919876543210&text=Hello&device=work"
```

---

## Webhook Configuration

Enable webhooks in the configuration (`POST /api/config`):

```json
{
  "webhook_enabled": true,
  "webhook_url": "https://your-server.com/webhook",
  "webhook_secret": "your-secret"
}
```

When a message is received, the server POSTs to your webhook URL:

```json
{
  "event": "message_received",
  "timestamp": "2026-02-26T10:00:00Z",
  "from": "919876543210",
  "message": "Hello",
  "is_group": false,
  "group_id": ""
}
```

If `webhook_secret` is set, the request includes an HMAC-SHA256 signature header:
```
X-Webhook-Signature: sha256=<hex>
```

---

## Security Notes

- Session credentials are stored in `session.db` — excluded from version control via `.gitignore`.
- `config.json` and `stats.db` are also excluded from version control.
- All admin endpoints require JWT Bearer token or HTTP Basic Auth.
- Per-IP rate limiting is enforced (default: 60 req/min, configurable via `RATE_LIMIT_RPM`).
- Security headers (CSP, HSTS, X-Frame-Options, etc.) are set on every response.
- The server enforces configurable daily and hourly send limits to reduce ban risk.
- Safe mode (enabled by default) caps sends at 50/day and 10/hour.
- Pairing requests are rate-limited to one attempt per phone number per 60 seconds.
- Enable HTTPS by setting `TLS_CERT_FILE` and `TLS_KEY_FILE` (TLS 1.2+ with strong ciphers).
- Intrusion detection locks IPs after 5 failed logins (30 min) or 10 failures (2 hours).

---

## Docker

### Build & Run with Docker

```bash
docker build -t wa-linker .
docker run -p 8080:8080 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=yourpassword \
  -e JWT_SECRET=yoursecret \
  -v $(pwd)/data:/app/data \
  wa-linker
```

### Docker Compose

```bash
# Copy and edit environment
cp .env.example .env  # or set vars in docker-compose.yml

docker-compose up -d
```

The service will be available at `http://localhost:8080`.

---

## Render.com Deployment

1. Fork this repository
2. Create a new **Web Service** on [Render](https://render.com)
3. Connect your GitHub repo
4. Render will auto-detect `render.yaml` and configure:
   - Go build with CGO enabled
   - PORT=10000
   - Auto-generated JWT_SECRET
   - 1 GB persistent disk at `/app/data`
5. Set `ADMIN_USER` and `ADMIN_PASS` in the Render dashboard environment variables

---

## API Key Authentication

In addition to JWT and Basic Auth, you can authenticate using API keys via the `X-API-Key` header.

### Manage API Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/keys` | List all API keys (values redacted) |
| POST | `/api/keys` | Create a new key (`{"name":"My App","role":"user"}`) |
| DELETE | `/api/keys?key=<key>` | Delete an API key |

### Using an API Key

```
GET /api/info
X-API-Key: wak_<your-key>
```

---

## Intrusion Detection

Failed login attempts are tracked per IP address:
- 5 failures → locked for **30 minutes**
- 10 failures → locked for **2 hours**

### Manage Lockouts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/lockouts` | List all locked/attempted IPs |
| DELETE | `/api/security/lockouts?ip=<ip>` | Unlock a specific IP |
| DELETE | `/api/security/lockouts` | Clear all lockouts |

---

## Bulk CSV Send

Send messages to multiple contacts by uploading a CSV file.

### CSV Format

```
phone,message
919876543210,Hello World
919876543211,Hi there
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/bulk-send` | Upload CSV (multipart `file` field), returns job ID |
| GET | `/api/bulk-send/jobs` | List all bulk send jobs |
| DELETE | `/api/bulk-send/jobs?id=<id>` | Delete a job |

---

## Delivery Reports

Message delivery status is tracked for sent messages.

```
GET /api/delivery?phone=<phone>
```

Returns sent messages with `delivery_status` (`pending`, `delivered`, `read`), `delivered_at`, and `read_at` timestamps.
