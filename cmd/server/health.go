package main

import (
	app "github.com/signbyte/signbyte-bff"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Portal-API (BFF)",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
