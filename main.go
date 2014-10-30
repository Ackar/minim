package main

import (
	"code.google.com/p/go-sqlite/go1/sqlite3"
	"code.google.com/p/goconf/conf"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Document struct {
	Id      int
	Title   string
	Content template.HTML
}

type DocumentEntry struct {
	Id    int
	Title string
}

type Login struct {
	Error string
	Email string
}

var db *sqlite3.Conn
var store = sessions.NewCookieStore([]byte("something-very-secret"))
var templates = template.Must(template.ParseFiles(
	"templates/index.html",
	"templates/edit.html",
	"templates/login.html"))

var validEmail = regexp.MustCompile("^.+@.+\\..+$")

/*

	HELPERS

*/

func getDocumentPath(id int) string {
	return fmt.Sprintf("documents/%d/doc.txt", id)
}

func getDocumentDir(id int) string {
	return fmt.Sprintf("documents/%d", id)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Return the user email and redirect to the login page if the user is not
// logged in.
func VerifyLogin(w http.ResponseWriter, r *http.Request) string {
	session, _ := store.Get(r, "login")
	email := ""
	if session.Values["email"] != nil {
		email = session.Values["email"].(string)
	}

	if email == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
	}

	return email
}

// Check if the user has the authorisation to access to the document with the
// given id
func CheckAuth(r *http.Request, id int) bool {
	session, _ := store.Get(r, "login")
	email := ""
	if session.Values["email"] != nil {
		email = session.Values["email"].(string)
	}

	_, err := db.Query("SELECT * FROM documents WHERE id=$1 AND email=$2", id, email)

	// If there is no correspond row then we get an io.EOF
	if err != nil {
		return false
	}

	return true
}

/*

	HANDLERS

*/

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	email := VerifyLogin(w, r)

	if email == "" {
		return
	}

	rows, err := db.Query("SELECT id, title FROM documents WHERE email=$1 ORDER BY last_update DESC", email)
	if err != nil && err != io.EOF {
		log.Println("Error when getting documents: ", err)
		return
	}

	documents := []DocumentEntry{}
	if err != io.EOF {
		for true {
			var id int
			var title string

			rows.Scan(&id, &title)
			documents = append(documents, DocumentEntry{id, title})

			if rows.Next() == io.EOF {
				break
			}
		}
	}

	renderTemplate(w, "index", documents)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var login Login

	email := strings.ToLower(r.FormValue("email"))
	password := r.FormValue("password")
	createButton := r.FormValue("create")
	loginButton := r.FormValue("login")

	login.Email = email
	hasError := false

	if loginButton != "" || createButton != "" {
		if email == "" || password == "" {
			login.Error = "Missing email or password."
			hasError = true
		} else {
			m := validEmail.FindStringSubmatch(email)
			if m == nil {
				login.Error = "Invalid email address."
				hasError = true
			}
		}
	}

	passwdSha1 := sha1.Sum([]byte(password))
	password = hex.EncodeToString(passwdSha1[:])

	session, _ := store.Get(r, "login")
	if !hasError && loginButton != "" {
		rows, err := db.Query("SELECT password FROM users WHERE email=$1", email)
		if err != nil {
			hasError = true
			login.Error = "Incorrect email and/or password."
		} else {
			var refPassword string
			rows.Scan(&refPassword)

			if password == refPassword {
				session.Values["email"] = email
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			} else {
				log.Println("Incorrect email and/or password.")
			}
		}
	}

	if !hasError && createButton != "" {
		err := db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", email, password)
		if err != nil {
			hasError = true
			login.Error = "Unable to create account."
		} else {
			session.Values["email"] = email
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	templates.ExecuteTemplate(w, "login.html", login)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "login")
	delete(session.Values, "email")
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func ImageHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		log.Println(err)
		return
	}

	if !CheckAuth(r, id) {
		http.Error(w, http.StatusText(403), 403)
		return
	}

	name := mux.Vars(r)["name"]

	img, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", getDocumentDir(id), name))
	if err != nil {
		log.Println("Error while reading image:", err)
	}

	w.Write(img)
}

func UploadImageHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		log.Println(err)
		return
	}

	if !CheckAuth(r, id) {
		http.Error(w, http.StatusText(403), 403)
		return
	}

	fileReader, header, err := r.FormFile("file")
	if err != nil {
		log.Println("Error while getting image file:", err)
		return
	}

	file, err := ioutil.ReadAll(fileReader)
	if err != nil {
		log.Println("Unable to read image file:", err)
		return
	}

	fileHash := sha1.Sum(file)
	ext := filepath.Ext(header.Filename)
	filename := hex.EncodeToString(fileHash[:]) + ext
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", getDocumentDir(id), filename), file, 0644)

	if err != nil {
		log.Println("Unable to write image file:", err)
	}

	log.Println("Writing:", filename)
	w.Write([]byte(filename))
}

func SaveHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Saving doc")
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		log.Println("Error while converting id:", err)
		return
	}

	if !CheckAuth(r, id) {
		http.Error(w, http.StatusText(403), 403)
		return
	}

	title := r.FormValue("title")
	if title != "" {
		err := db.Exec("UPDATE documents SET title=$1, last_update=CURRENT_TIMESTAMP WHERE id=$2", title, id)
		if err != nil {
			log.Println("Error while saving title:", err)
		}
	}

	content := r.FormValue("content")
	if content != "" {
		err := ioutil.WriteFile(getDocumentPath(id), []byte(content), 0644)
		if err != nil {
			log.Println(err)
		}
	}
}

func EditHandler(w http.ResponseWriter, r *http.Request) {
	email := VerifyLogin(w, r)
	if email == "" {
		return
	}

	doc := new(Document)

	var err error
	doc.Id, err = strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	rows, err := db.Query("SELECT title, email FROM documents WHERE id=$1", doc.Id)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	defer rows.Close()
	var docEmail string
	rows.Scan(&doc.Title, &docEmail)

	if docEmail != email {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	content, err := ioutil.ReadFile(getDocumentPath(doc.Id))
	doc.Content = template.HTML(content)

	if err != nil {
		log.Println(err)
	}

	templates.ExecuteTemplate(w, "edit.html", doc)
}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		log.Println(err)
	}

	if !CheckAuth(r, id) {
		http.Error(w, http.StatusText(403), 403)
		return
	}

	err = db.Exec("DELETE FROM documents WHERE id=" + strconv.Itoa(id))
	if err != nil {
		log.Println(err)
	}

	err = os.RemoveAll(getDocumentDir(id))

	if err != nil {
		log.Println(err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func NewDocumentHandler(w http.ResponseWriter, r *http.Request) {
	email := VerifyLogin(w, r)
	if email == "" {
		return
	}

	// Create the new entry in the BDD
	err := db.Exec("INSERT INTO documents(email, title) VALUES ($1, 'New Document')", email)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		return
	}

	id := int(db.LastInsertId())

	// Create the new corresponding file
	os.Mkdir(getDocumentDir(id), 0755)
	ioutil.WriteFile(getDocumentPath(id), make([]byte, 0), 0644)

	http.Redirect(w, r, fmt.Sprintf("/edit/%d", id), http.StatusFound)
}

func InitDB() {
	sqlCreateTable := `
	create table documents (id INTEGER NOT NULL PRIMARY KEY, email TEXT, title TEXT, last_update DATETIME DEFAULT CURRENT_TIMESTAMP);
	create table users (email TEXT NOT NULL PRIMARY KEY, password TEXT NOT NULL);
	`

	err := db.Exec(sqlCreateTable)
	if err != nil {
		log.Println("Error while creating tables:", err)
		return
	}
}

func main() {
	config, err := conf.ReadConfigFile("minim.conf")
	if err != nil {
		log.Fatal("Unable to parse config file:", err)
	}

	port, err := config.GetString("default", "port")
	if err != nil {
		log.Fatal("Config file error:", err)
	}

	newDb, err := sqlite3.Open("./minim.sql")
	if err != nil {
		log.Fatal(err)
	}

	db = newDb
	InitDB()

	// Ensure the `documents' directory exists
	os.Mkdir("documents", 0755)

	r := mux.NewRouter()

	fs := http.FileServer(http.Dir("static"))

	r.Schemes("https")

	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/new", NewDocumentHandler)
	r.HandleFunc("/save", SaveHandler)
	r.HandleFunc("/image/{id:[0-9]+}/{name:[.a-z0-9]+}", ImageHandler)
	r.HandleFunc("/uploadimage/{id:[0-9]+}", UploadImageHandler)
	r.HandleFunc("/edit/{id:[0-9]+}", EditHandler)
	r.HandleFunc("/delete/{id:[0-9]+}", DeleteHandler)

	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/", r)

	log.Println("Listening...")
	http.ListenAndServe(":"+port, nil)
}
