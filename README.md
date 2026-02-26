# wa-linker — WhatsApp Automation Server

A Go-based WhatsApp automation server built on the [`whatsmeow`](https://github.com/tulir/whatsmeow) library. It exposes a simple HTTP API for pairing a WhatsApp account, sending messages, scheduling messages, and monitoring activity — all with built-in anti-ban protection.

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

| Variable     | Default    | Description                                      |
|--------------|------------|--------------------------------------------------|
| `PORT`       | `8080`     | HTTP port the server listens on                  |
| `ADMIN_USER` | `admin`    | Username for HTTP Basic Auth on admin endpoints  |
| `ADMIN_PASS` | `admin123` | Password for HTTP Basic Auth on admin endpoints  |

> ⚠️ **Security:** Always set `ADMIN_USER` and `ADMIN_PASS` to strong values in production. The server will log a warning on startup if you use the defaults.

---

## API Endpoints

### Public

| Method | Path         | Description                               |
|--------|--------------|-------------------------------------------|
| GET    | `/`          | Serve the main web UI                     |
| GET    | `/pair`      | Generate a WhatsApp pairing code (`?phone=<number>`) |
| GET    | `/is-linked` | Returns `true`/`false` — device link status |

### Admin (HTTP Basic Auth required)

| Method | Path             | Description                          |
|--------|------------------|--------------------------------------|
| GET    | `/admin`         | Serve the admin web UI               |
| GET    | `/api/info`      | WhatsApp connection info             |
| GET    | `/api/config`    | Get current configuration            |
| POST   | `/api/config`    | Update configuration (JSON body)     |
| GET    | `/api/logs`      | Retrieve recent system logs          |
| GET    | `/api/stats`     | Message statistics and ban warnings  |
| GET    | `/api/security`  | Security status overview             |
| GET    | `/api/schedule`  | List all scheduled messages          |
| POST   | `/api/schedule`  | Add a scheduled message (JSON body: `{"phone":"...","message":"...","scheduled_at":"<RFC3339>"}`) |
| GET    | `/logout`        | Log out the linked WhatsApp device   |
| GET    | `/send`          | Send a message (`?phone=<number>&text=<message>`) |

---

## Security Notes

- Session credentials are stored in `session.db` — this file is excluded from version control via `.gitignore`.
- `config.json` is also excluded from version control.
- The server enforces configurable daily and hourly send limits to reduce ban risk.
- Safe mode (enabled by default) caps sends at 50/day and 10/hour.
- Pairing requests are rate-limited to one attempt per phone number per 60 seconds.
- All pairing requests are logged with the caller's IP address.
- Set `ADMIN_USER` and `ADMIN_PASS` environment variables before running in production.
