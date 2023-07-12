package main

import (
	"log"
	"net/http"
	"os"

	"github.com/FreddyTheApp/auth/pkg/handlers"
	"github.com/FreddyTheApp/auth/pkg/repository"
	"github.com/FreddyTheApp/auth/pkg/services"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var (
	mongoUri    = ""
	mongoDBName = "freddy"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Printf("Error loading .env file: %v", err)
	}
	mongoUri = os.Getenv("MONGO_CONN")
	if mongoUri == "" {
		log.Fatal("MONGO_CONN not set")
		return
	}
}

func main() {
	log.Println("Starting...")
	repo := repository.NewUserRepository(mongoUri, mongoDBName)
	service := services.NewUserService(repo)
	handler := handlers.NewUserHandler(service)

	r := mux.NewRouter()

	r.HandleFunc("/", handler.IndexHandler).Methods("GET")
	r.HandleFunc("/signup", handler.SignUpHandler).Methods("POST")
	r.HandleFunc("/signin", handler.SignInHandler).Methods("POST")
	r.HandleFunc("/refresh", handler.RefreshTokenHandler).Methods("POST")
	r.HandleFunc("/validate-token", handler.ValidateTokenHandler).Methods("POST")
	r.HandleFunc("/verify", handler.VerifyEmailHandler).Methods("GET")

	http.ListenAndServe(":8080", r)
}
