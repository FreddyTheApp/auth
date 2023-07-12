package user

type User struct {
	ID                     string `json:"id"`
	Email                  string `json:"email"`
	Password               string `json:"password"`
	IsEmailVerified        bool   `bson:"isEmailVerified"`
	EmailVerificationToken string `bson:"emailVerificationToken"`
}
