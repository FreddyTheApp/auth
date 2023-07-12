package services

import (
	"context"
	"os"
	"time"

	"github.com/FreddyTheApp/auth/api/user"
	"github.com/FreddyTheApp/auth/pkg/repository"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo *repository.UserRepository
}

func NewUserService(repo *repository.UserRepository) *UserService {
	return &UserService{
		repo: repo,
	}
}

func (s *UserService) SignUp(ctx context.Context, u *user.User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hashedPassword)

	return s.repo.Save(ctx, u)
}

func (s *UserService) SignIn(ctx context.Context, email, password string) (string, string, error) {
	u, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return "", "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		return "", "", err
	}

	jwtToken, err := s.generateToken(u.Email)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateToken(u.Email)
	if err != nil {
		return "", "", err
	}

	// Save the refresh token in the DB
	err = s.repo.SaveRefreshToken(ctx, u.Email, refreshToken)
	if err != nil {
		return "", "", err
	}

	return jwtToken, refreshToken, nil
}

func (s *UserService) RefreshToken(ctx context.Context, email, refreshToken string) (string, string, error) {
	u, err := s.repo.FindRefreshToken(ctx, email, refreshToken)
	if err != nil {
		return "", "", err
	}

	// Generate new tokens
	jwtToken, err := s.generateToken(u.Email)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.generateToken(u.Email)
	if err != nil {
		return "", "", err
	}

	// Save new refresh token in the DB
	err = s.repo.SaveRefreshToken(ctx, u.Email, refreshToken)
	if err != nil {
		return "", "", err
	}

	return jwtToken, refreshToken, nil
}

func (s *UserService) generateToken(email string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})

	// Replace 'yourSigningKey' with a suitable secret for signing the JWT
	jwtToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}
