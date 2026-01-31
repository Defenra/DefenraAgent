package assets

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed injected/*
var injectedFS embed.FS

//go:embed html/challenge_template.html
var challengeTemplateFS embed.FS

// GetInjectedFileSystem returns an http.FileSystem for the injected assets
func GetInjectedFileSystem() http.FileSystem {
	// Sub returns a filesystem starting at the given subtree
	// We want to serve files from inside "injected/", not including the folder itself in the path
	fsys, err := fs.Sub(injectedFS, "injected")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}

// GetChallengeTemplate returns the challenge template content
func GetChallengeTemplate() ([]byte, error) {
	return challengeTemplateFS.ReadFile("html/challenge_template.html")
}
