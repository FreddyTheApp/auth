package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/FreddyTheApp/auth/api/user"
	"github.com/FreddyTheApp/auth/pkg/services"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserHandler struct {
	service *services.UserService
}

func NewUserHandler(service *services.UserService) *UserHandler {
	return &UserHandler{
		service: service,
	}
}

func (h *UserHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var u user.User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.service.SignUp(r.Context(), &u)
	if err != nil {
		// Handling if email already exists
		if we, ok := err.(mongo.WriteException); ok {
			for _, e := range we.WriteErrors {
				if e.Code == 11000 {
					http.Error(w, fmt.Sprintf("email %s already exists", u.Email), http.StatusConflict)
					return
				}
			}
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *UserHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	var u user.User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jwtToken, refreshToken, err := h.service.SignIn(r.Context(), u.Email, u.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with both tokens
	json.NewEncoder(w).Encode(map[string]string{
		"jwtToken":     jwtToken,
		"refreshToken": refreshToken,
	})
}

func (h *UserHandler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	token := r.URL.Query().Get("token")

	jwtToken, refreshToken, err := h.service.RefreshToken(r.Context(), email, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with both tokens
	json.NewEncoder(w).Encode(map[string]string{
		"jwtToken":     jwtToken,
		"refreshToken": refreshToken,
	})
}

func (h *UserHandler) ValidateTokenHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Token string `json:"token"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	isVaild, email, err := h.service.ValidateToken(r.Context(), request.Token)

	if err != nil {
		json.NewEncoder(w).Encode(struct {
			IsValid bool `json:"isValid"`
		}{
			IsValid: false,
		})
		return
	}

	if isVaild {
		json.NewEncoder(w).Encode(struct {
			IsValid bool   `json:"isValid"`
			Email   string `json:"email"`
		}{
			IsValid: true,
			Email:   email,
		})
	} else {
		json.NewEncoder(w).Encode(struct {
			IsValid bool   `json:"isValid"`
			Email   string `json:"email"`
		}{
			IsValid: false,
			Email:   email,
		})
	}
}

func (h *UserHandler) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the verification token from the request.
	email := r.URL.Query().Get("email")
	token := r.URL.Query().Get("token")

	// Use the service layer to verify the token.
	err := h.service.VerifyEmailToken(email, token)
	if err != nil {
		// If there was an error, respond with an error message.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If verification was successful, respond with a success message.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Email verification successful"))
}
