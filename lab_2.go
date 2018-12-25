package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/gocraft/web"
	"github.com/golang/glog"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// Context - main
type Context struct {
	err    error
	access bool
}

// Document - структура для вывода одного документа
type Document struct {
	ID      int      `json:"id"`
	Name    string   `json:"name"`
	Mime    string   `json:"mime"`
	Public  string   `json:"public"`
	File    string   `json:"file"`
	Created string   `json:"created"`
	Grant   []string `json:"grant,omitempty"`
}

// Documents - список документов
type Documents struct {
	File string `json:"file,omitempty"`
	Dcs  []*Document `json:"documents,omitempty"`
}

// Errors - вывод ошибок
type Errors struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// Result - остальные ответы
type Result struct {
	Login string `json:"login,omitempty"`
	Token string `json:"token,omitempty"`
}

// Output - main output view
type Output struct {
	Error    *Errors   `json:"error,omitempty"`
	Response *Result  `json:"response,omitempty"`
	Data     *Documents `json:"data,omitempty"`
}

var (
	lock    sync.RWMutex
	db      *sqlx.DB
	err     error
	storage = make(map[string]string)
)

func main() {

	flag.Set("logtostderr", "true")
	flag.Set("v", "2")
	flag.Parse()

	b, err := ioutil.ReadFile("./db_pass.txt") // db_pass.txt: "username:password"
	if err != nil {
		glog.Fatal(err)
	}

	connStr := "postgres://" + strings.TrimRight(string(b), "\r\n") + "@localhost/documents?sslmode=disable"

	db, err = sqlx.Connect("pgx", connStr)
	if err != nil {
		glog.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		glog.Fatal(err)
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for _ = range ticker.C {
			err := ClearSessionTable()
			if err != nil {
				glog.Fatal(err)
			}
		}
	}()

	router := web.New(Context{}).
		Middleware((*Context).Logs).
		Middleware((*Context).Error).
		Middleware((*Context).AuthCheck).
		Get("/auth", (*Context).AuthPage).
		Get("/documents", (*Context).Documents).
		Get("/documents/:id", (*Context).Document).
		Get("/load", (*Context).DocumentsLoad).
		Get("/logout", (*Context).Logout).
		Post("/create", (*Context).DocumentsCreate).
		Post("/authform", (*Context).Auth).
		Delete("/documents/:id", (*Context).DelDoc).
		NotFound((*Context).NotFound)

	if err := http.ListenAndServe("localhost:9000", router); err != nil {
		glog.Fatal(err)
	}

}

//ClearSessionTable - чистка токенов, которые не активны более 5 минут
func ClearSessionTable() (err error) {
	query := `delete from session_table where starttime < current_timestamp - interval '5 minutes';`
	_, err = db.Exec(query)
	if err != nil {
		err = errors.Wrap(err, "Clear session db error")
		return
	}
	return
}

//Logs - alternative logger
func (c *Context) Logs(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	start := time.Now()
	next(rw, req)
	glog.Infof("[ %s ][ %s ] %s", time.Since(start), req.Method, req.URL)
}

//AuthCheck - check user authorization
func (c *Context) AuthCheck(rw web.ResponseWriter, r *web.Request, next web.NextMiddlewareFunc) {

	token := r.URL.Query().Get("token")

	if strings.Contains(r.URL.Path, "authform") {
		next(rw, r)
		return
	}

	if strings.Contains(r.URL.Path, "create") {
		next(rw, r)
		return
	}

	if token == "" {
		if strings.Contains(r.URL.Path, "documents") {
			c.access = false
			next(rw, r)
			return
		}

		c.AuthPage(rw, r)
		next(rw, r)
		return
	}

	var chname sql.NullString
	err := db.QueryRow("select un from session_table where suuid = $1", token).Scan(&chname)
	if err != nil {
		rw.WriteHeader(401) // TODO можно сделать и получше :)
		c.err = errors.Wrap(err, "Query db error")
		return
	}

	_, err = db.Exec("update session_table set starttime = NOW()::timestamp where suuid = $1;", token)
	if err != nil {
		c.err = errors.Wrap(err, "Update session db error")
		return
	}

	if strings.Contains(r.URL.Path, "documents") {
		if chname.Valid {
			c.access = true
			next(rw, r)
			return

		}
		c.access = false
		next(rw, r)
		return

	}
	if !chname.Valid {
		rw.WriteHeader(401)
		return

	}
	next(rw, r)

}

// AuthPage - Authentication page
func (c *Context) AuthPage(rw web.ResponseWriter, req *web.Request) {

	lock.Lock()
	storage = make(map[string]string)
	lock.Unlock()

	http.ServeFile(rw, req.Request, "templates/auth.html")
}

//Auth - Authentication func
func (c *Context) Auth(rw web.ResponseWriter, req *web.Request) {

	user := req.FormValue("login")

	chpass := sha256.Sum256([]byte(req.FormValue("pass")))
	passhash := hex.EncodeToString(chpass[:])

	text := `select username from users where username = $1 and pass = $2;`
	var checkname sql.NullString
	err = db.QueryRow(text, user, passhash).Scan(&checkname)
	if err != nil {
		rw.WriteHeader(401)
		c.err = errors.New("Access denied - Unauthorized")
		return
	}

	uu, err := uuid.NewV4()
	if err != nil {
		c.err = errors.Wrap(err, "UUID generate error")
		return
	}
	uuStr := uu.String()

	_, err = db.Exec("insert into session_table (un, suuid) values ($1, $2);", user, uuStr)
	if err != nil {
		c.err = errors.Wrap(err, "Insert to (session) db error")
		return
	}

	output := &Output{
		Response: &Result{
			Token: uuStr,
		},
	}
	c.Show(rw, req, output)
}

// Logout - delete session token
func (c *Context) Logout(rw web.ResponseWriter, req *web.Request) {

	lock.Lock()
	storage = make(map[string]string)
	lock.Unlock()

	token := req.URL.Query().Get("token")
	_, err = db.Exec("delete from session_table where suuid = $1;", token)
	if err != nil {
		c.err = errors.Wrap(err, "Delete from db error")
		return
	}
	output := &Output{
		Response: &Result{
			Token: token,
		},
	}
	c.Show(rw, req, output)
}

//Documents - Output all documents with filters (key = value, limit)
func (c *Context) Documents(rw web.ResponseWriter, req *web.Request) {

	key := req.URL.Query().Get("key")
	value := req.URL.Query().Get("value")
	limitstr := req.URL.Query().Get("limit")

	var limit int
	if limitstr != "" {
		limit, err = strconv.Atoi(limitstr)
		if err != nil {
			c.err = errors.Wrap(err, "Wrong limit format")
			return
		}
	}

	a := "close"
	if c.access {
		a = "open"
	}

	documents := "Documents" + key + value + limitstr + a
	lock.RLock()
	data, ok := storage[documents]
	lock.RUnlock()

	if ok {
		rw.Header().Set("Content-Type", "application/json")

		_, err = io.WriteString(rw, data)
		if err != nil {
			c.err = errors.Wrap(err, "Read cache error")

			lock.Lock()
			storage = make(map[string]string)
			lock.Unlock()
			return
		}

	} else {

		output := &Output{
			Data: &Documents{
				Dcs: make([]*Document, 0, 100),
			},
		}
		var document *Document
		var rows *sqlx.Rows

		filter := ""
		limits := ""
		args := []interface{}{}
		possibleFilters := map[string]string{
			"name":    "name",
			"mime":    "mime",
			"public":  "public",
			"filedir": "filedir",
			"created": "created",
		}

		ac := ""
		if !c.access {
			ac = ` and public = true `
		}

		if key != "" && value != "" {
			args = append(args, value)
			filter = fmt.Sprintf(` and %s = ? `, possibleFilters[key])
		}

		if limit != 0 {
			args = append(args, limit)
			limits = ` limit ? ;`
		}
		text := `
			select id, name, mime, public, filedir, created
			from documents_table
			where true
			` + filter + ac + `
			order by name ASC, created ASC
			` + limits

		rows, err = db.Queryx(db.Rebind(text), args...)
		if err != nil {
			c.err = errors.Wrap(err, "Query to db error")
			return
		}
		defer rows.Close()

		for rows.Next() {
			document = new(Document)
			err = rows.Scan(&document.ID, &document.Name, &document.Mime, &document.Public, &document.File, &document.Created)
			if err != nil {
				c.err = errors.Wrap(err, "Scan db error")
				return
			}
			output.Data.Dcs = append(output.Data.Dcs, document)
		}

		if err = rows.Err(); err != nil {
			c.err = errors.Wrap(err, "Error query/scan db")
			return
		}

		var mr []byte
		mr, err = json.Marshal(output)
		if err != nil {
			c.err = errors.Wrap(err, "Documents Marshaling error")
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(mr)

		lock.Lock()
		defer lock.Unlock()
		storage[documents] = string(mr)
	}

}

//Document - Output one document by id
func (c *Context) Document(rw web.ResponseWriter, req *web.Request) {

	idstr := req.PathParams["id"]
	idint, err := strconv.Atoi(idstr)
	if err != nil {
		rw.WriteHeader(400)
		c.err = errors.Wrap(err, "Wrong id format")
		return
	}

	content := "documents_ctype_" + idstr
	onedoc := "documents" + idstr

	lock.RLock()
	data, ok1 := storage[onedoc]
	ct, ok2 := storage[content]
	lock.RUnlock()

	if ok1 && ok2 {
		rw.Header().Set("Content-Disposition", ct)

		_, err = io.WriteString(rw, data)
		if err != nil {
			c.err = errors.Wrap(err, "Read cache error")

			lock.Lock()
			storage = make(map[string]string)
			lock.Unlock()
			return
		}

	} else {

		var rows *sqlx.Rows
		args := []interface{}{}
		args = append(args, idint)

		ac := ""
		if c.access == false {
			ac = ` and public = true`
		}

		text := `
			select id, name, mime, public, filedir, created, hname
			from documents_table
			where id = ? ` + ac
		rows, err = db.Queryx(db.Rebind(text), args...)
		if err != nil {
			c.err = errors.Wrap(err, "Query db error")
			return
		}
		defer rows.Close()

		var document *Document
		var hashname string
		for rows.Next() {
			document = new(Document)
			err = rows.Scan(&document.ID, &document.Name, &document.Mime, &document.Public, &document.File, &document.Created, &hashname)
			if err != nil {
				c.err = errors.Wrap(err, "Scan db error")
				return
			}
		}

		if err = rows.Err(); err != nil {
			c.err = errors.Wrap(err, "Error query/scan db")
			return
		}

		if hashname == "" {
			c.NotFound(rw, req)
			return
		}

		filePath := filepath.Join("files", hashname)
		b, err := ioutil.ReadFile(filePath)
		if err != nil {
			c.err = errors.Wrap(err, "Readfile error")
			return
		}

		attachment := "attachment; filename=" + document.Name
		rw.Header().Set("Content-Disposition", attachment)
		rw.Write(b)

		lock.Lock()
		storage[onedoc] = string(b)
		storage[content] = attachment
		lock.Unlock()
	}
}

//NotFound page
func (c *Context) NotFound(rw web.ResponseWriter, req *web.Request) {

	output := &Output{
		Error: &Errors{
			Code: 404,
			Text: "Page Not Found",
		},
	}

	var mr []byte
	mr, err = json.Marshal(output)
	if err != nil {
		c.err = errors.Wrap(err, "Documents Marshaling error")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusNotFound)
	rw.Write(mr)

}

//Error
func (c *Context) Error(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	next(rw, req)

	if c.err != nil {
		fmt.Println(c.err)
		var text string
		var code int

		switch rw.StatusCode() {
		case 500:
			code = 500
			text = "Нежданчик"
		case 400:
			code = 400
			text = "Некорректные параметры"
		case 401:
			code = 401
			text = "Не авторизован"
		case 403:
			code = 403
			text = "Нет прав доступа"
		case 405:
			code = 405
			text = "Неверный метод запроса"
		case 501:
			code = 501
			text = "Метод не реализован"
		default:
			code = rw.StatusCode()
			text = c.err.Error()
		}
		output := &Output{
			Error: &Errors{
				Code: code,
				Text: text,
			},
		}
		c.Show(rw, req, output)
		return
	}
}

//DocumentsLoad - load page
func (c *Context) DocumentsLoad(rw web.ResponseWriter, req *web.Request) {
	http.ServeFile(rw, req.Request, "templates/load.html")
	rw.Header().Set("Content-Type", "multipart/form-data")
}

//DocumentsCreate - load, save document and document info to db
func (c *Context) DocumentsCreate(rw web.ResponseWriter, req *web.Request) {

	if err := req.ParseMultipartForm(32 << 20); err != nil { // 32Mb max file upload size
		c.err = errors.Wrap(err, "Parsing Multiform error")
		return
	}

	file, handler, err := req.FormFile("uploadfile")
	if err != nil {
		c.err = errors.Wrap(err, "Parsing Form error")
		return
	}
	defer file.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.err = errors.Wrap(err, "Copy file from buffer error")
		return
	}
	hash := sha256.Sum256(buf.Bytes())
	hname := hex.EncodeToString(hash[:])

	fileSavePath := filepath.Join("files", hname)
	if err = ioutil.WriteFile(fileSavePath, buf.Bytes(), os.ModePerm); err != nil {
		c.err = errors.Wrap(err, "Write file error")
		return
	}

	filename := handler.Filename
	mime := handler.Header.Get("Content-Type")
	public := req.FormValue("pub")
	filedir := req.FormValue("fd")

	text := `insert into documents_table (name, mime, public, filedir, hname)
	values ($1, $2, $3, $4, $5);`

	_, err = db.Exec(text, filename, mime, public, filedir, hname)
	if err != nil {
		c.err = errors.Wrap(err, "Insert to db error")
		return
	}

	lock.Lock()
	storage = make(map[string]string)
	lock.Unlock()

	output := &Output{
		Data: &Documents{
			File: filename,
		},
	}
	c.Show(rw, req, output)
}

// DelDoc - delete func
func (c *Context) DelDoc(rw web.ResponseWriter, req *web.Request) {

	token := req.URL.Query().Get("token")
	if token == "" {
		rw.WriteHeader(401)
		c.err = errors.New("Access denied - Unauthorized")
		return
	}

	idstr := req.PathParams["id"]
	idint, err := strconv.Atoi(idstr)
	if err != nil {
		c.err = errors.Wrap(err, "Wrong id format")
		return
	}

	var hn sql.NullString
	err = db.QueryRow("select hname from documents_table where id = $1;", idint).Scan(&hn)
	if err != nil {
		c.err = errors.Wrap(err, "Query db error")
		return
	}

	if err = os.Remove(filepath.Join("files", hn.String)); err != nil {
		c.err = errors.Wrap(err, "Remove file from dir (files/) error")
		return
	}

	lock.Lock()
	storage = make(map[string]string)
	lock.Unlock()

	_, err = db.Exec("delete from documents_table where id = $1;", idint)
	if err != nil {
		c.err = errors.Wrap(err, "Delete from db error")
		return
	}

	output := &Output{
		Response: &Result{
			Token: token,
		},
	}
	c.Show(rw, req, output)
}

//Show - вывод ответа
func (c *Context) Show(rw web.ResponseWriter, req *web.Request, output *Output) {
	var mr []byte
	mr, err = json.MarshalIndent(output, "  ", "  ")
	if err != nil {
		c.err = errors.Wrap(err, "Marshaling error")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(mr)
}