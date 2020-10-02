package main

import (
	//	"fmt"
	//"crypto/rand"
	//"crypto/rsa"
	"fmt"

	"net/http"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	//"context"
	//"github.com/kelseyhightower/envconfig"
	//"github.com/labstack/echo"
	//"github.com/labstack/echo/middleware"
	//"github.com/shellhub-io/shellhub/api/apicontext"
	//"github.com/shellhub-io/shellhub/api/pkg/dbtest"
	//"github.com/shellhub-io/shellhub/api/routes"
	//"github.com/shellhub-io/shellhub/api/store/mongo"
	//mgo "go.mongodb.org/mongo-driver/mongo"
	//"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/shellhub-io/shellhub/pkg/models"
)

type config struct {
	MongoHost string `envconfig:"mongo_host" default:"mongo"`
	MongoPort int    `envconfig:"mongo_port" default:"27017"`
}

// Echo JWT token authentication tests.
//
// This test is executed for the EchoHandler() in two modes:
//  - via http client
//  - via http.Handler
func testAPI(e *httpexpect.Expect) {
	type Login struct {
		Username string `form:"username"`
		Password string `form:"password"`
	}

	//publicAPI := e.Group("/api")
	//internalAPI := e.Group("/internal")

	e.POST("/api/login").WithForm(Login{"username", "<bad password>"}).
		Expect().
		Status(http.StatusUnauthorized)

	r := e.POST("/api/login").WithForm(Login{"username", "password"}).
		Expect().
		Status(http.StatusOK).JSON().Object()

	r.Keys().ContainsOnly("user", "name", "tenant", "email", "token")

	token := r.Value("token").String().Raw()
	tenant := r.Value("tenant").String().Raw()
	_ = tenant
	/*s := e.GET("/api/auth/user").WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).JSON().Object()
	s.Keys().ContainsOnly("user", "name", "tenant", "email", "token")*/
	//esta rota funciona fora do container e dentro nao

	//privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	authReq := &models.DeviceAuthRequest{
		Info: &models.DeviceInfo{
			ID:         "id",
			PrettyName: "Pretty name",
			Version:    "test",
		},
		DeviceAuth: &models.DeviceAuth{
			TenantID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			Identity: &models.DeviceIdentity{
				MAC: "mac",
			},
			PublicKey: "key",
		},
	}

	t := e.POST("/api/devices/auth").WithJSON(authReq).
		Expect().
		Status(http.StatusOK).
		JSON().Object()
	t.Keys().ContainsOnly("name", "namespace", "token", "uid")
	t.Value("name").Equal("mac")
	t.Value("namespace").Equal("username")
	uid := t.Value("uid").String().Raw()

	u := e.GET(fmt.Sprintf("/api/devices/%s", uid)).
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Object()
	u.Value("identity").Object().Value("mac").Equal("mac")

	device := map[string]interface{}{
		"identity": map[string]string{
			"mac": "mac",
		},
		"info": map[string]string{
			"id":          "id",
			"pretty_name": "Pretty name",
			"version":     "test",
		},
		"name":       "mac",
		"namespace":  "username",
		"public_key": "key",
		"status":     "pending",
		"tenant_id":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
	}
	u.ContainsMap(device)

	array := e.GET("/api/devices").
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Array()

	for _, val := range array.Iter() {
		val.Object().ContainsMap(device)
	}
	e.GET(fmt.Sprintf("/internal/auth/token/%s", tenant)).
		Expect().
		Status(http.StatusOK)

	data := map[string]interface{}{
		"name": "newName",
	}

	_ = data

	/*v := e.PATCH(fmt.Sprintf("/api/devices/%s", uid)).
		WithHeader("Authorization", "Bearer "+token).
		WithJSON(data).
		Expect().
		Status(http.StatusOK)
	_ = v

	/* w := e.PATCH(fmt.Sprintf("/api/devices/%s/accepted", uid)).
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK)
	_ = w

	x := e.DELETE(fmt.Sprintf("/api/devices/%s", uid)).
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK)
	_ = x */

	// Test for public session routes
	//set a session uid that exists
	uid_session := "b1efa6dbcdefcb03629628d61e5d74da7647dd1c14126e537f53451afd805c1f"
	su := e.GET(fmt.Sprintf("/api/sessions/%s", uid_session)).
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Object()
	su.Value("authenticated").Equal(true)

	spu := e.GET(fmt.Sprintf("/api/sessions/%s/play", uid_session)).
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Array()
	spu.First().Object().Value("width").Equal(110)

	array = e.GET("/api/sessions").
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Array()
	fmt.Println(array)

	// public tests for stats
	array = e.GET("/api/stats").
		WithHeader("Authorization", "Bearer "+token).
		Expect().
		Status(http.StatusOK).
		JSON().Array()
	fmt.Println(array)

	//public tests for change username

	status_array := []int{http.StatusOK, http.StatusOK, http.StatusConflict, http.StatusUnauthorized}

	forms_array := []interface{}{
		map[string]interface{}{ // successfull email and username change
			"username":        "newusername",
			"email":           "new@email.com",
			"currentPassword": "",
			"newPassword":     "",
		},
		map[string]interface{}{ // successfull password change
			"username":        "",
			"email":           "",
			"currentPassword": "password",
			"newPassword":     "new_password_hash",
		},
		map[string]interface{}{ //conflict
			"username":        "username",
			"email":           "new@email.com",
			"currentPassword": "",
			"newPassword":     "",
		},
		map[string]interface{}{ // unauthorized
			"username":        "",
			"email":           "",
			"currentPassword": "wrong_password",
			"newPassword":     "new_password",
		},
	}
	//var n *httpexpect.Expect //fix type
	for i, v := range forms_array {
		n := e.PUT("/api/user").
			WithHeader("Authorization", "Bearer "+token).
			WithJSON(v).
			Expect().
			Status(status_array[i])
		fmt.Println(n)
	}
	/*e.GET(fmt.Sprintf("/internal/token/%s", tenant)).
			Expect().
			Status(http.StatusOK)
	/*

		/*
			e.GET("/restricted/hello").
				Expect().
				Status(http.StatusBadRequest)

			e.GET("/restricted/hello").WithHeader("Authorization", "Bearer <bad token>").
				Expect().
				Status(http.StatusUnauthorized)

			e.GET("/restricted/hello").WithHeader("Authorization", "Bearer "+token).
				Expect().
				Status(http.StatusOK).Body().Equal("hello, world!")

			auth := e.Builder(func(req *httpexpect.Request) {
				req.WithHeader("Authorization", "Bearer "+token)
			})

			auth.GET("/restricted/hello").
				Expect().
				Status(http.StatusOK).Body().Equal("hello, world!")
	*/
}

func TestEchoClient(t *testing.T) {

	e := httpexpect.WithConfig(httpexpect.Config{
		// prepend this url to all requests
		BaseURL: "http://api:8080/",

		// use http.Client with a cookie jar and timeout
		Client: &http.Client{
			Jar:     httpexpect.NewJar(),
			Timeout: time.Second * 30,
		},

		// use fatal failures
		Reporter: httpexpect.NewRequireReporter(t),

		// use verbose logging
		Printers: []httpexpect.Printer{
			httpexpect.NewCurlPrinter(t),
			httpexpect.NewDebugPrinter(t, true),
		},
	})
	testAPI(e)

}

/*
func TestEchoHandler(t *testing.T) {
	handler := echo.New()
	handler.Use(middleware.Logger())

	/*var cfg config
	if err := envconfig.Process("api", &cfg); err != nil {
		panic(err.Error())
	}

	// Set client options
	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%d", cfg.MongoHost, cfg.MongoPort))
	// Connect to MongoDB
	client, err := mgo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err)
	}

	if err := mongo.ApplyMigrations(client.Database("test")); err != nil {
		panic(err)
	}*/ /*

	handler.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			db := dbtest.DBServer{}
			defer db.Stop()
			store := mongo.NewStore(db.Client().Database("main"))
			ctx := apicontext.NewContext(store, c)

			return next(ctx)
		}
	})

	publicAPI := handler.Group("/api")
	internalAPI := handler.Group("/internal")

	internalAPI.GET(routes.AuthRequestURL, apicontext.Handler(routes.AuthRequest), apicontext.Middleware(routes.AuthMiddleware))
	publicAPI.POST(routes.AuthDeviceURL, apicontext.Handler(routes.AuthDevice))
	publicAPI.POST(routes.AuthDeviceURLV2, apicontext.Handler(routes.AuthDevice))
	publicAPI.POST(routes.AuthUserURL, apicontext.Handler(routes.AuthUser))
	publicAPI.POST(routes.AuthUserURLV2, apicontext.Handler(routes.AuthUser))
	publicAPI.GET(routes.AuthUserURLV2, apicontext.Handler(routes.AuthUserInfo))
	internalAPI.GET(routes.AuthUserTokenURL, apicontext.Handler(routes.AuthGetToken))

	publicAPI.PUT(routes.UpdateUserURL, apicontext.Handler(routes.UpdateUser))

	publicAPI.GET(routes.GetDeviceListURL, apicontext.Handler(routes.GetDeviceList))
	publicAPI.GET(routes.GetDeviceURL, apicontext.Handler(routes.GetDevice))
	publicAPI.DELETE(routes.DeleteDeviceURL, apicontext.Handler(routes.DeleteDevice))
	publicAPI.PATCH(routes.RenameDeviceURL, apicontext.Handler(routes.RenameDevice))
	internalAPI.POST(routes.OfflineDeviceURL, apicontext.Handler(routes.OfflineDevice))
	internalAPI.GET(routes.LookupDeviceURL, apicontext.Handler(routes.LookupDevice))
	publicAPI.PATCH(routes.UpdateStatusURL, apicontext.Handler(routes.UpdatePendingStatus))

	publicAPI.GET(routes.GetSessionsURL, apicontext.Handler(routes.GetSessionList))
	publicAPI.GET(routes.GetSessionURL, apicontext.Handler(routes.GetSession))
	internalAPI.PATCH(routes.SetSessionAuthenticatedURL, apicontext.Handler(routes.SetSessionAuthenticated))
	internalAPI.POST(routes.CreateSessionURL, apicontext.Handler(routes.CreateSession))
	internalAPI.POST(routes.FinishSessionURL, apicontext.Handler(routes.FinishSession))
	internalAPI.POST(routes.RecordSessionURL, apicontext.Handler(routes.RecordSession))
	publicAPI.GET(routes.PlaySessionURL, apicontext.Handler(routes.PlaySession))

	publicAPI.GET(routes.GetStatsURL, apicontext.Handler(routes.GetStats))

	e := httpexpect.WithConfig(httpexpect.Config{
		Client: &http.Client{
			Transport: httpexpect.NewBinder(handler),
			Jar:       httpexpect.NewJar(),
		},
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewDebugPrinter(t, true),
		},
	})

	testAPI(e)
}*/
