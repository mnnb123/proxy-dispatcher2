// Package webui exposes the embedded static web panel assets.
package webui

import "embed"

//go:embed login.html dashboard.html app.js style.css
var Files embed.FS
