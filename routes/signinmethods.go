package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signbyte-bff/routes/response"
)

// signInMethods tells the sign-in page which ways of signing in this deployment
// offers, as the Auth Service publishes them, so a page shows no way it would
// refuse (the eID card through the provider's own plugin, legacyEid, only where
// the deployment turns it on). Anonymous: it is asked before anyone signs in.
//
// @operationId PortalSignInMethods
// @title Ways to sign in
// @success 200 SignInMethods response.SignInMethods "The ways to sign in, in the Auth Service's order"
// @route /api/portal/v1/sign-in-methods [get].
func (r *router) signInMethods(ctx *azugo.Context) {
	methods, err := r.SignInMethods().Get(ctx)
	if err != nil {
		ctx.Log().Warn("the ways to sign in the Auth Service offers are not current", zap.Error(err))
	}
	if methods == nil {
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithTitle("The ways to sign in cannot be read right now")))

		return
	}

	ctx.JSON(&response.SignInMethods{Methods: methods})
}
