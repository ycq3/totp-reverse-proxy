// totp_reverse_proxy.go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/natefinch/lumberjack" // use logrotate package
	"github.com/pquerna/otp/totp"
)

var (
	sessionCookie = "PSESSION"
	sessionMaxAge = 30 * time.Minute
	loginPage     = `
    <html>
    <body>
        <form method="POST" action="/login">
            <input type="text" name="code" placeholder="Enter code">
            <input type="hidden" name="redirect" value="{{.EncodedRedirect}}">
            <input type="submit" value="Login">
            {{if .WrongCode}}
                <p style="color: red;">{{ .Message}}</p>
            {{end}}
        </form>
    </body>
    </html>`
)

type LoginPageData struct {
	EncodedRedirect string
	WrongCode       bool
	Message         string
}

const loginFailureMessage = "Wrong code. Please try again."
const expiredSessionmessage = "Session expired. Please login again."

var sessions map[string]time.Time
var tmpl *template.Template

type TOTPReverseProxy struct {
	secretKey string
	targetURL string
	server    *http.Server
	useHTTPS  bool
	certFile  string
	keyFile   string
}

func NewTOTPReverseProxy(addr, secretKey, targetURL string, useHTTPS bool, certFile, keyFile string, logDirectory string) *TOTPReverseProxy {
	sessions = make(map[string]time.Time)
	tmpl = template.Must(template.New("login").Parse(loginPage))
	proxy := NewLoggingReverseProxy(targetURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == "POST" {
			code := r.FormValue("code")
			redirectEncoded := r.FormValue("redirect")
			redirectURLBytes, err := base64.URLEncoding.DecodeString(redirectEncoded)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			redirectURL := string(redirectURLBytes)
			if isValidOTP(secretKey, code) && redirectURL != "" {
				// If OTP is valid, create a new session and set the session cookie
				sessionID := createSession()
				setSessionCookie(w, sessionID)
				// Store the session in the sessions map
				sessions[sessionID] = time.Now().Add(sessionMaxAge)
				// Redirect the user back to the original proxied URL
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			// If OTP is invalid or redirect URL is missing,
			// show login page again with 401 status
			w.WriteHeader(http.StatusUnauthorized)
			data := LoginPageData{
				EncodedRedirect: base64.URLEncoding.EncodeToString([]byte(redirectURL)),
				WrongCode:       true,
				Message:         loginFailureMessage,
			}
			tmpl.Execute(w, data)
			return
		}

		// Check if the session is valid
		sessionID := getSessionID(r)
		statusCode, isValid := isValidSession(sessionID)
		if !isValid {
			redirectURL := r.URL.String()
			// If the session is not valid, display the login page
			w.WriteHeader(statusCode)
			//fmt.Fprintf(w, loginPage, url.QueryEscape(r.URL.String()))
			data := LoginPageData{
				EncodedRedirect: base64.URLEncoding.EncodeToString([]byte(redirectURL)),
				WrongCode:       true,
				Message:         expiredSessionmessage,
			}
			tmpl.Execute(w, data)
			return
		}

		// If the session is valid, serve the request using the reverse proxy
		proxy.ServeHTTP(w, r)
	})

	setupLogger(logDirectory + "proxy-access.log")

	loggedMux := loggingMiddleware(mux)

	server := &http.Server{
		Addr:         addr,
		Handler:      loggedMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	return &TOTPReverseProxy{
		secretKey: secretKey,
		targetURL: targetURL,
		server:    server,
		useHTTPS:  useHTTPS,
		certFile:  certFile,
		keyFile:   keyFile,
	}
}

func setupLogger(logFilePath string) {
	log.SetOutput(&lumberjack.Logger{
		Filename:   logFilePath, // path to the log file
		MaxSize:    10,          // megabytes
		MaxBackups: 3,           // maximum number of log files to retain
		MaxAge:     28,          // days
		Compress:   true,        // compress old log files
	})
	log.SetPrefix("[Proxy] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

func (proxy *TOTPReverseProxy) Start() error {
	if proxy.useHTTPS {
		return proxy.server.ListenAndServeTLS(proxy.certFile, proxy.keyFile)
	}
	return proxy.server.ListenAndServe()
}

func (proxy *TOTPReverseProxy) Stop() error {
	return proxy.server.Shutdown(context.TODO())
}

func isValidOTP(secretKey, code string) bool {
	return totp.Validate(code, secretKey)
}

// Generate a random session ID
func createSession() string {
	sessionIDBytes := make([]byte, 18)
	_, err := rand.Read(sessionIDBytes)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(sessionIDBytes)
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	expiration := time.Now().Add(sessionMaxAge)
	cookie := http.Cookie{
		Name:     sessionCookie,
		Value:    sessionID,
		Expires:  expiration,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func isValidSession(sessionID string) (int, bool) {
	expiration, ok := sessions[sessionID]
	if !ok {
		return http.StatusUnauthorized, false
	}
	if expiration.Before(time.Now()) {
		return http.StatusForbidden, false
	}
	return http.StatusOK, true
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := NewLoggingResponseWriter(w)

		defer func() {
			duration := time.Since(start)
			sessionID := getSessionID(r)
			if sessionID == "" {
				sessionID = "-"
			}
			log.Printf("%s %s %s \"%s\" %d %d \"%s\" \"%s\"",
				r.RemoteAddr,
				sessionID,
				r.Method,
				r.URL.Path,
				rw.statusCode,
				rw.contentLength,
				duration,
				r.UserAgent(),
			)
		}()
		// Security measures
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Feature-Policy", "gexceedsLimiteolocation 'self'; camera 'none'")
		w.Header().Set("X-Frame-Options", "deny")
		next.ServeHTTP(rw, r)
	})
}

// LoggingResponseWriter is a custom http.ResponseWriter that captures
// status code and content length.
type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int
}

// NewLoggingResponseWriter creates a new LoggingResponseWriter.
func NewLoggingResponseWriter(w http.ResponseWriter) *LoggingResponseWriter {
	return &LoggingResponseWriter{w, http.StatusOK, 0}
}

// WriteHeader wraps the original WriteHeader method to capture the status code.
func (lrw *LoggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Write wraps the original Write method to capture the content length.
func (lrw *LoggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.contentLength += n
	return n, err
}

func NewLoggingReverseProxy(target string) http.Handler {
	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Error parsing target URL: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ServeHTTP(w, r)
	})
}
