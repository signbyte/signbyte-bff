package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/signbyte-bff/session"
)

// Per-request context keys for the resolved session.
const (
	ctxSessionID = "portal.session_id"
	ctxSession   = "portal.session"
)

// csrfHeader is the header the browser must echo on state-changing requests.
const csrfHeader = "X-CSRF-Token"

// requireSession resolves the session cookie to the server-held session, failing
// closed when it is absent or expired. On state-changing requests it also requires
// the anti-forgery token to match the one minted for this session.
func (r *router) requireSession() azugo.RequestHandlerFunc {
	cookieName := r.Config().CookieName

	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			sid := ctx.Cookie.Get(cookieName)
			if sid == "" {
				ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
					pkerrors.WithDetail("no session")))

				return
			}

			sess, err := r.Sessions().GetSession(ctx, sid)
			if err != nil {
				clearSessionCookies(ctx, cookieName)
				ctx.Error(pkerrors.NewProblem("err:session:unauthorized",
					pkerrors.WithDetail("session expired")))

				return
			}

			if stateChanging(string(ctx.Method())) {
				if sess.CSRF == "" || ctx.Header.Get(csrfHeader) != sess.CSRF {
					r.csrfDenied(ctx, sess)
					ctx.Error(pkerrors.NewProblem("err:session:csrf",
						pkerrors.WithStatus(fasthttp.StatusForbidden),
						pkerrors.WithDetail("missing or invalid anti-forgery token")))

					return
				}
			}

			ctx.SetUserValue(ctxSessionID, sid)
			ctx.SetUserValue(ctxSession, sess)
			next(ctx)
		}
	}
}

// csrfDenied records the anti-forgery rejection as a typed security event: a
// state-changing request arrived on a LIVE session without its anti-forgery
// token, which is the cross-site request-forgery shape this gate exists to
// refuse — an attack signal, unlike a plain expired-session 401 (the normal
// re-login path, which stays a request log). Emission is best-effort; the
// refusal itself never depends on it.
func (r *router) csrfDenied(ctx *azugo.Context, sess *session.Session) {
	sec := r.SecEvents()
	if sec == nil {
		return
	}
	if err := sec.AuthZDenied(ctx, secevents.Denial{
		Actor:  broker.Actor{ID: sess.Subject, Type: "user"},
		Reason: "anti-forgery token missing or mismatched on a state-changing request",
	}); err != nil {
		ctx.Log().Error("secevents denied emit failed", zap.Error(err))
	}
}

// sessionFromCtx returns the session + its id resolved by requireSession.
func sessionFromCtx(ctx *azugo.Context) (string, *session.Session) {
	sid, _ := ctx.UserValue(ctxSessionID).(string)
	sess, _ := ctx.UserValue(ctxSession).(*session.Session)

	return sid, sess
}

func stateChanging(method string) bool {
	switch method {
	case fasthttp.MethodGet, fasthttp.MethodHead, fasthttp.MethodOptions:
		return false
	default:
		return true
	}
}
