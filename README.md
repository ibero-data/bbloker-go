# bbloker-go

Go SDK for [bbloker](https://bbloker.com) — block AI scrapers, bots, and unwanted crawlers from your API. Zero dependencies, stdlib only.

## Installation

```bash
go get github.com/ibero-data/bbloker-go
```

## Quick Start

```go
package main

import (
	"net/http"
	"os"

	bbloker "github.com/ibero-data/bbloker-go"
)

func main() {
	blocker := bbloker.New(bbloker.Config{
		APIKey: os.Getenv("BBLOKER_API_KEY"),
	})
	defer blocker.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	http.ListenAndServe(":3000", blocker.Handler(mux))
}
```

### chi

```go
r := chi.NewRouter()
r.Use(blocker.Handler)
```

### gorilla/mux

```go
r := mux.NewRouter()
r.Use(blocker.Handler)
```

## Config

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `APIKey` | `string` | — | API key from the bbloker dashboard (required) |
| `APIURL` | `string` | `https://bbloker.com` | API endpoint |
| `SyncInterval` | `time.Duration` | `5m` | How often to fetch updated rules |
| `FlushInterval` | `time.Duration` | `10s` | Telemetry batch flush interval |
| `BufferSize` | `int` | `100` | Max buffered fingerprints before force flush |
| `Telemetry` | `*bool` | `true` | Enable/disable telemetry reporting |
| `RateLimit` | `int` | `60` | Max requests per IP per window |
| `RateLimitWindow` | `time.Duration` | `60s` | Rate limit sliding window |
| `OnBlock` | `func(w, r, Decision)` | 403 | Custom block handler |

## How It Works

Every request passes through a 5-check detection pipeline:

1. **User-Agent** — substring match against 40 known bot UAs (0.95 confidence)
2. **IP** — CIDR match against known bot IP ranges (0.90 confidence)
3. **Rate limit** — per-IP sliding window (0.70 confidence)
4. **Header anomaly** — regex patterns on headers with weighted scoring
5. **Allow** — request passes through

Rules sync from the bbloker API in the background. Fingerprints are batched and reported for the dashboard.

## License

MIT — see [bbloker.com](https://bbloker.com) for terms.
