// echo is a tiny static HTTP server for the integration tests: it reports who called it and
// which identity it runs as.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		groups, _ := os.Getgroups()
		fmt.Fprintf(w, "remote=%s uid=%d gid=%d groups=%v\n", host, os.Getuid(), os.Getgid(), groups)
	})
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
