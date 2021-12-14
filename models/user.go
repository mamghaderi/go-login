package models

import (
	"github.com/jinzhu/gorm"
)

//User struct declaration
type User struct {
	gorm.Model

	Email    string `gorm:"type:varchar(100);unique_index"`
	Password string `json:"Password"`
	IsVerified bool `json:"IsVerified"`
}

//VerificationCode struct declaration
// Type could be EmailVerification, or ForgotPassword
type VerificationCode struct{
	gorm.Model

	Email    string `gorm:"type:varchar(100)"`
	Code     int `json:"Code"`
	CodeType string `json:"CodeType"`
}

//ForgotPassword struct declaration
type ForgotPassword struct{
	Email    string `gorm:"type:varchar(100);unique_index"`
	Code     int `json:"Code"`
	NewPassword string `json:"NewPassword"`
}
