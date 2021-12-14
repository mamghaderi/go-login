package controllers

import (
	"auth/models"
	"auth/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"math/rand"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type ErrorResponse struct {
	Err string
}

type error interface {
	Error() string
}

var db = utils.ConnectDB()

func TestAPI(w http.ResponseWriter, r *http.Request) {
	var resp = map[string]interface{}{"status": true, "message": "Live"}
	json.NewEncoder(w).Encode(resp)
}

func Login(w http.ResponseWriter, r *http.Request) {
	user := &models.User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Invalid request"}
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := FindOne(user.Email, user.Password)
	json.NewEncoder(w).Encode(resp)
}

func FindOne(email, password string) map[string]interface{} {
	user := &models.User{}

	if err := db.Where("Email = ?", email).First(user).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Email address not found"}
		return resp
	}
	if user.IsVerified == false{
		var resp = map[string]interface{}{"status": false, "message": "Email not verified, please verify your email then try to login"}
		return resp
	}
	expiresAt := time.Now().Add(time.Minute * 100000).Unix()
	errf := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if errf != nil && errf == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		var resp = map[string]interface{}{"status": false, "message": "Invalid login credentials. Please try again"}
		return resp
	}

	tk := &models.Token{
		UserID: user.ID,
		Email:  user.Email,
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)

	tokenString, error := token.SignedString([]byte("secret"))
	if error != nil {
		fmt.Println(error)
	}

	var resp = map[string]interface{}{"status": true, "message": "logged in"}
	resp["token"] = tokenString //Store the token in the response
	return resp
}

//CreateUser function -- create a new user
func CreateUser(w http.ResponseWriter, r *http.Request) {

	user := &models.User{}
	json.NewDecoder(r.Body).Decode(user)

	pass, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		err := ErrorResponse{
			Err: "Password Encryption  failed",
		}
		json.NewEncoder(w).Encode(err)
	}

	user.Password = string(pass)
	user.IsVerified = false

	createdUser := db.Create(user)
	var errMessage = createdUser.Error

	if createdUser.Error != nil {
		fmt.Println(errMessage)
		var resp = map[string]interface{}{"status": false, "message": errMessage}
        json.NewEncoder(w).Encode(resp)
        return
	}
	a := createdUser.Value
	a.(*models.User).Password = ""
	json.NewEncoder(w).Encode(a)

}

func VerifyEmailCode(w http.ResponseWriter, r *http.Request){
    body := &models.VerificationCode{}
	json.NewDecoder(r.Body).Decode(body)

	verify := &models.VerificationCode{}
	if err := db.Where("Email = ? AND Code_Type = ?", body.Email, "EmailVerification").Last(verify).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Verification code not found"}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if verify.Code != body.Code{
	    var resp = map[string]interface{}{"status": false, "message": "Wrong verification code"}
		json.NewEncoder(w).Encode(resp)
		return
	}

	user := &models.User{}
	db.Where("Email = ?", body.Email).First(user)
	user.IsVerified = true
	if db.Save(&user).Error != nil{
	    var resp = map[string]interface{}{"status": false, "message": "Something went wrong, try later"}
	    json.NewEncoder(w).Encode(resp)
	    return
	}

	db.Delete(&verify)

	var resp = map[string]interface{}{"status": true, "message": "The Email address verified successfully"}
	json.NewEncoder(w).Encode(resp)
}

func SendEmailCode(w http.ResponseWriter, r *http.Request){
    body := &models.VerificationCode{}
	json.NewDecoder(r.Body).Decode(body)
	user := &models.User{}
	if err := db.Where("Email = ?", body.Email).First(user).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Email address not found"}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if user.IsVerified == true{
	    var resp = map[string]interface{}{"status": false, "message": "Already verified"}
		json.NewEncoder(w).Encode(resp)
		return
	}
    rand.Seed(time.Now().UnixNano())
    var randomCode = rand.Intn(9999 - 1000) + 1000
    fmt.Println(randomCode)

    code := &models.VerificationCode{
        Email: user.Email,
        Code:  randomCode,
        CodeType: "EmailVerification",
    }

	if db.Save(&code).Error != nil{
	    var resp = map[string]interface{}{"status": false, "message": "Can not generate code, try later"}
	    json.NewEncoder(w).Encode(resp)
	    return
	}
    var resp = map[string]interface{}{"status": true, "message": "Check logs in terminal to see the code"}
    json.NewEncoder(w).Encode(resp)
}

//FetchCurrentUser function -- return user details from extracted token
func FetchCurrentUser(w http.ResponseWriter, r *http.Request) {
    var id = r.Context().Value("user")
    var user models.User
	db.First(&user, id)
	user.Password = ""
	json.NewEncoder(w).Encode(&user)
}


func ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := &models.User{}
	var id = r.Context().Value("user")
	db.First(&user, id)

	body := &models.User{}
	json.NewDecoder(r.Body).Decode(body)

    pass, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println(err)
        var resp = map[string]interface{}{"status": false, "message": "Password Encryption failed"}
        json.NewEncoder(w).Encode(resp)
        return
    }
    user.Password = string(pass)
    db.Save(&user)
    user.Password = ""
	json.NewEncoder(w).Encode(&user)
}

func VerifyPassword(w http.ResponseWriter, r *http.Request){
    body := &models.ForgotPassword{}
	json.NewDecoder(r.Body).Decode(body)

	verify := &models.VerificationCode{}
	if err := db.Where("Email = ? AND Code_Type = ?", body.Email, "ForgotPassword").Last(verify).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Verification code not found"}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if verify.Code != body.Code{
	    var resp = map[string]interface{}{"status": false, "message": "Wrong verification code"}
		json.NewEncoder(w).Encode(resp)
		return
	}

	user := &models.User{}
	if err := db.Where("Email = ?", body.Email).First(user).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Email address not found"}
		json.NewEncoder(w).Encode(resp)
		return
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println(err)
        var resp = map[string]interface{}{"status": false, "message": "Password Encryption failed"}
        json.NewEncoder(w).Encode(resp)
        return
    }
    user.Password = string(pass)
    db.Save(&user)

    var resp = map[string]interface{}{"status": true, "message": "Password Changed successfully"}
    json.NewEncoder(w).Encode(resp)
}

func ForgotPassword(w http.ResponseWriter, r *http.Request){
    body := &models.VerificationCode{}
	json.NewDecoder(r.Body).Decode(body)
	user := &models.User{}
	if err := db.Where("Email = ?", body.Email).First(user).Error; err != nil {
		var resp = map[string]interface{}{"status": false, "message": "Email address not found"}
		json.NewEncoder(w).Encode(resp)
		return
	}

    rand.Seed(time.Now().UnixNano())
    var randomCode = rand.Intn(9999 - 1000) + 1000
    fmt.Println(randomCode)

    code := &models.VerificationCode{
		Email: user.Email,
		Code:  randomCode,
		CodeType: "ForgotPassword",
	}

	if db.Save(&code).Error != nil{
	    var resp = map[string]interface{}{"status": false, "message": "Can not generate code, try later"}
	    json.NewEncoder(w).Encode(resp)
	    return
	}
    var resp = map[string]interface{}{"status": true, "message": "Check logs in terminal to see the code"}
    json.NewEncoder(w).Encode(resp)
}
