package bbloker

import "net/http"

// Handler returns middleware compatible with net/http, chi, gorilla/mux, and
// any router that accepts func(http.Handler) http.Handler.
func (b *Bbloker) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision := b.Analyze(r)

		// Report telemetry (non-blocking).
		fp := buildFingerprint(r)
		go b.telemetry.push(fp)

		if decision.Action == "block" {
			if b.config.OnBlock != nil {
				b.config.OnBlock(w, r, decision)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
