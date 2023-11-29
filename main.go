package main

import (
	
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)



var CredentialsMap map[string]string
var Session map[string]string
var key = []byte("this is my kingdom")

type MyClaims struct{
	jwt.RegisteredClaims
	Sesssion string
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("Invalid Request Type")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	user := r.FormValue("username")
	if user == "" {
		msg := url.QueryEscape("Username cannot be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	paswrd := r.FormValue("password")
	if paswrd == "" {
		msg := url.QueryEscape("Password cannot be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	hashedPassword, ok := CredentialsMap[user]
	if !ok {
		msg := url.QueryEscape("Username does not exist")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}



	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(paswrd))
	if err != nil {
		msg := url.QueryEscape("Credentials do not match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	ssid:=uuid.New().String()
	Session[ssid]=user
	token,err:=createToken(ssid)
	if err!=nil{
		fmt.Errorf("Error while Generating Token %w",err)
	}
	c:=http.Cookie{
		Name: "sessionID",
		Value: token,
	}
	http.SetCookie(w,&c)


	msg := url.QueryEscape("You logged in " + user)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}


func HomePage(w http.ResponseWriter, r *http.Request) {
	c , err:=r.Cookie("sessionID")
	if err!=nil{
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}
	s, err := parseToken(c.Value)
	fmt.Println(s)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var e string
	if s != "" {
		e = Session[s]
	}



	msg := r.FormValue("msg")
	fmt.Println(msg)

	fmt.Fprintf(w,`<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login Form</title>
	</head>
	<body>
		<h1>Welcome to the screen!</h1> 
		<h1>IF YOU HAVE A SESSION, HERE IS YOUR EMAIL: %s</h1>
		<h2>%s</h2>
		<h1>Register User</h1>
		<form action="/register" method="POST">
			<input type="text" name="username">
			<input type="password" name="password">
			<input type="submit">
		</form>
		<h1>Login User</h1>
		<form action="/login" method="POST">
			<input type="text" name="username">
			<input type="password" name="password">
			<input type="submit">
		</form>
	</body>
	</html>`,e,msg)
}


func iterateover(credsmap map[string]string){
	for key, value:=range credsmap{
		fmt.Println("username:",key)
		fmt.Println("password:",value)
	}
}


func Register(w http.ResponseWriter, r *http.Request){
	if r.Method!=http.MethodPost{
		fmt.Errorf("Invalid Request Type")
	}
	user:=r.FormValue("username")
	if user==""{
		msg:=url.QueryEscape("Username cannot be empty")
		http.Redirect(w,r,"/msg="+msg,http.StatusSeeOther)
		return
	}

	paswrd:=r.FormValue("password")
	if paswrd==""{
		msg:=url.QueryEscape("Password cannot be empty")
		http.Redirect(w,r,"/msg="+msg,http.StatusSeeOther)
		return
	}
	
	
	generatedPassword,err:=bcrypt.GenerateFromPassword([]byte(paswrd),bcrypt.DefaultCost)
	if err!=nil{
		fmt.Errorf("Error occured while generating hashed password %w",err)
	}
	fmt.Println(user)
	fmt.Println(paswrd)
	fmt.Println(generatedPassword)
	CredentialsMap[user]=string(generatedPassword)
	iterateover(CredentialsMap)
	http.Redirect(w,r,"/",http.StatusSeeOther)
}

func createToken(session string)(string,error){

	cc:=MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5*time.Minute)),
		},
		Sesssion: session,
	}
	
	token:=jwt.NewWithClaims(jwt.SigningMethodHS256,cc)
	signedToken,err:=token.SignedString(key)
	if err!=nil{
		fmt.Errorf("Error Occured While signing a token %w",err)
	}
	return signedToken,nil

}

func parseToken(ss string)(string,error){
	token,err:=jwt.ParseWithClaims(ss, &MyClaims{}, func(t *jwt.Token)(interface{},error){
		if t.Method.Alg()!=jwt.SigningMethodHS256.Alg(){
			return nil, fmt.Errorf("Your algorithm does not match with the one we provided from our server")
		}
		return key,nil
	})

	if err != nil {
		return "", fmt.Errorf("couldn't ParseWithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}
	return token.Claims.(*MyClaims).Sesssion,nil
}

func main() {
	
	CredentialsMap=make(map[string]string)
	Session=make(map[string]string)
	CredentialsMap["test"]="test"

	http.HandleFunc("/",HomePage)
	http.HandleFunc("/register",Register)
	http.HandleFunc("/login",login)

	

	log.Fatal(http.ListenAndServe(":8080",nil))
}

// package main

// import ("sync"
// "fmt")

// func Home(val func (a,b int)int, ref int)int{
// 	return val(2,3)+ref
// }

// func sender(ch chan int, wg *sync.WaitGroup){
// 	defer wg.Done()

// 	for i:=0;i<5;i++{
// 		ch<-i
// 		fmt.Println("Value sent from the sender :",i)
// 	}
// 	close(ch)
// }

// func receiver(ch chan int, wg *sync.WaitGroup){
// 	defer wg.Done()

// 	for{
// 		value,ok:=<-ch
// 		if !ok{

// 			fmt.Println("Channel is closed or no longer sending the value")
// 			break
// 		}
// 		fmt.Println("Value received from the channel is :",value)
// 	}
// }


// func main(){
// 	var wg sync.WaitGroup
// 	ch:=make(chan int)
// 	wg.Add(2)
// 	go sender(ch,&wg)
// 	go receiver(ch,&wg)

// 	ans:=Home(func (a,b int)int{
// 		return a+b
// 	},4)
// 	fmt.Println(ans)

// 	wg.Wait()
// }