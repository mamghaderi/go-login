package routes

import (
	"auth/controllers"
	"auth/utils/auth"
	"net/http"

	"github.com/gorilla/mux"
)

func Handlers() *mux.Router {

	r := mux.NewRouter().StrictSlash(true)
	r.Use(CommonMiddleware)

	r.HandleFunc("/", controllers.TestAPI).Methods("GET")
	r.HandleFunc("/register", controllers.CreateUser).Methods("POST")
	r.HandleFunc("/email/sendcode", controllers.SendEmailCode).Methods("POST")
	r.HandleFunc("/email/verify", controllers.VerifyEmailCode).Methods("POST")
	r.HandleFunc("/login", controllers.Login).Methods("POST")
	r.HandleFunc("/forgotpass/sendcode", controllers.ForgotPassword).Methods("POST")
	r.HandleFunc("/forgotpass/verify", controllers.VerifyPassword).Methods("POST")

	// Auth route
	s := r.PathPrefix("/auth").Subrouter()
	s.Use(auth.JwtVerify)
    s.HandleFunc("/me", controllers.FetchCurrentUser).Methods("GET")
	s.HandleFunc("/changepass", controllers.ChangePassword).Methods("PUT")
	return r
}

// CommonMiddleware --Set content-type
func CommonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header")
		next.ServeHTTP(w, r)
	})
}
