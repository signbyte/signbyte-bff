package routes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	docgate "github.com/gmb-lib/go-docgate"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	answer "github.com/gmb-lib/go-validation-answer"

	"github.com/signbyte/signbyte-bff/audit"
)

// verifyDocument — POST /api/portal/v1/verify (multipart: file). PUBLIC — the
// one anonymous endpoint besides login: anyone may check a signed document
// without an account. The flow is a stateless proxy: the file is admission-
// checked (only a signed PDF / ASiC-E goes anywhere), forwarded to the signing
// service under this service's own identity, and the provider's report is
// normalized into the shared validation answer. The bytes are never parsed
// beyond the admission check, never persisted, and never logged here; abuse is
// contained by the per-IP rate limit + concurrency gate + the size cap, and
// every request leaves a purpose-scoped evidence event (fail-open — evidence
// must never block a legitimate verification).
func (r *router) verifyDocument(ctx *azugo.Context) {
	if r.Verify() == nil {
		ctx.Error(pkerrors.NewProblem("err:verify:unavailable",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("verify not configured")))
		return
	}

	ip := verifyClientIP(ctx)
	if !r.verifyGate.acquire(ip) {
		ctx.Error(pkerrors.NewProblem("err:verify:tooManyRequests",
			pkerrors.WithStatus(fasthttp.StatusTooManyRequests),
			pkerrors.WithTitle("Too many requests"),
			pkerrors.WithPublicDetail("another verification is already running for this address — wait for it to finish")))
		return
	}
	defer r.verifyGate.release(ip)

	files := ctx.Form.Files("file")
	if len(files) != 1 {
		ctx.Error(pkerrors.NewProblem("err:verify:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithPublicDetail("multipart/form-data with exactly one 'file' part is required")))
		return
	}
	fh := files[0]

	maxBytes := r.Config().VerifyMaxBytes
	if fh.Size > maxBytes {
		ctx.Error(pkerrors.NewProblem("err:verify:fileTooLarge",
			pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
			pkerrors.WithTitle("File too large"),
			pkerrors.WithPublicDetail("the file exceeds the size limit")))
		return
	}

	f, err := fh.Open()
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:verify:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	_ = f.Close()
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:verify:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
		return
	}
	if int64(len(data)) > maxBytes {
		ctx.Error(pkerrors.NewProblem("err:verify:fileTooLarge",
			pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
			pkerrors.WithTitle("File too large"),
			pkerrors.WithPublicDetail("the file exceeds the size limit")))
		return
	}

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	// The document gate: only a signed PDF or a signed, well-formed ASiC-E is
	// forwarded — everything else is rejected here with a typed reason, so
	// garbage never consumes provider quota.
	if _, err := docgate.Check(docgate.ModeVerify, fh.Filename, data, docgate.WithMaxBytes(maxBytes)); err != nil {
		r.recordVerify(ctx, ip, fh.Size, sha, "rejected", "")
		switch {
		case errors.Is(err, docgate.ErrTooLarge):
			ctx.Error(pkerrors.NewProblem("err:verify:fileTooLarge",
				pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
				pkerrors.WithTitle("File too large"),
				pkerrors.WithPublicDetail("the file exceeds the size limit")))
		case errors.Is(err, docgate.ErrNoSignature):
			ctx.Error(pkerrors.NewProblem("err:verify:notSigned",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Document is not signed"),
				pkerrors.WithPublicDetail("the document carries no signature to validate")))
		case errors.Is(err, docgate.ErrUnsupportedType):
			ctx.Error(pkerrors.NewProblem("err:verify:unsupportedType",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Unsupported file type"),
				pkerrors.WithPublicDetail("only a signed PDF or ASiC-E container (.pdf, .asice, .edoc, .sce) can be verified")))
		default:
			ctx.Error(pkerrors.NewProblem("err:verify:malformed",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Malformed document"),
				pkerrors.WithDetail(err.Error()),
				pkerrors.WithPublicDetail("the file is not a well-formed signed document")))
		}
		return
	}

	res, err := r.Verify().Validate(ctx, fh.Filename, data)
	if err != nil {
		ctx.Log().Warn("verify upstream call failed", zap.Error(err))
		r.recordVerify(ctx, ip, fh.Size, sha, "error", "")
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))
		return
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		r.recordVerify(ctx, ip, fh.Size, sha, "upstream-rejected", res.SessionID)
		// The signing service answers problem+json for its own rejections;
		// relay those. A provider-native error body (not a problem) becomes a
		// typed answer: a semantic 4xx means "the provider cannot validate
		// this document", anything else is an upstream failure.
		if down, ok := pkerrors.ParseProblem(res.Report); ok {
			outer := res.StatusCode
			if outer >= fasthttp.StatusInternalServerError {
				outer = fasthttp.StatusBadGateway
			}
			ctx.Error(pkerrors.Relay(down, r.AppName, outer))
			return
		}
		if res.StatusCode >= 400 && res.StatusCode < 500 {
			ctx.Error(pkerrors.NewProblem("err:verify:notValidatable",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Document cannot be validated"),
				pkerrors.WithPublicDetail("the validation provider could not process this document")))
			return
		}
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))
		return
	}

	v, err := answer.NormalizeReport(res.Report)
	if err != nil {
		ctx.Log().Warn("verify report unreadable", zap.Error(err))
		r.recordVerify(ctx, ip, fh.Size, sha, "unreadable-report", res.SessionID)
		ctx.Error(pkerrors.NewProblem("err:upstream:unexpectedResponse",
			pkerrors.WithStatus(fasthttp.StatusBadGateway),
			pkerrors.WithDetail("the validation report could not be read")))
		return
	}
	// A verify answer is always fresh — stamp the moment it ran (validation is
	// time-anchored; the answer is rendered "as of" this moment).
	v.ValidatedAt = time.Now().UTC().Format(time.RFC3339)

	r.recordVerify(ctx, ip, fh.Size, sha, v.Verdict, res.SessionID)
	ctx.JSON(v)
}

// recordVerify emits the abuse-evidence event for one verify request,
// fire-and-forget.
func (r *router) recordVerify(ctx *azugo.Context, ip string, size int64, sha, verdict, sessionID string) {
	r.VerifyAudit().Record(audit.VerifyEvent{
		TS:            time.Now().UTC().Format(time.RFC3339),
		IP:            ip,
		UserAgent:     ctx.UserAgent(),
		SizeBytes:     size,
		SHA256:        sha,
		Verdict:       verdict,
		CorrelationID: correlation.FromContext(ctx).CorrelationID,
		SessionID:     sessionID,
	})
}

// verifyClientIP resolves the originating client address: the gateway-set
// X-Forwarded-For first hop (the edge gateway must strip/overwrite it on
// inbound client traffic — the trusted-proxy assumption the whole stack runs
// under), falling back to the connection peer for direct in-network calls.
func verifyClientIP(ctx *azugo.Context) string {
	v := ctx.Header.Get("X-Forwarded-For")
	if v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}

		return strings.TrimSpace(v)
	}
	if ip := ctx.IP(); ip != nil {
		return ip.String()
	}

	return ""
}

// inflightGate caps concurrently running requests per client key. A public
// verification legitimately runs tens of seconds, so without this a single
// address could pin many slow upstream sessions inside its rate-limit budget.
type inflightGate struct {
	mu    sync.Mutex
	max   int
	perIP map[string]int
}

func newInflightGate(maxPerKey int) *inflightGate {
	if maxPerKey < 1 {
		maxPerKey = 1
	}

	return &inflightGate{max: maxPerKey, perIP: make(map[string]int)}
}

// acquire reserves a slot for key, reporting false when the key is at its cap.
func (g *inflightGate) acquire(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.perIP[key] >= g.max {
		return false
	}
	g.perIP[key]++

	return true
}

// release frees key's slot, dropping the map entry at zero so the map only
// ever holds in-flight keys.
func (g *inflightGate) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if n := g.perIP[key]; n <= 1 {
		delete(g.perIP, key)
	} else {
		g.perIP[key] = n - 1
	}
}
