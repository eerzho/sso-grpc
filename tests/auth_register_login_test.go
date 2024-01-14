package tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/eerzho/protos/gen/go/sso"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"sync"
	"testing"
	"time"
)

const (
	emptyAppId    = 0
	appId         = 1
	appSecret     = "test-secret"
	paaDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appId,
	})

	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})

	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)

	assert.True(t, ok)
	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appId, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTtl).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_Login_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})

	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name     string
		email    string
		password string
		exErr    string
	}{
		{
			name:     "Register with Empty Password",
			email:    gofakeit.Email(),
			password: "",
			exErr:    "password is required",
		},
		{
			name:     "Register with Empty Email",
			email:    "",
			password: randomFakePassword(),
			exErr:    "email is required",
		},
		{
			name:     "Register with BothEmpty",
			email:    "",
			password: "",
			exErr:    "email is required",
		},
	}

	var wg sync.WaitGroup

	for _, tt := range tests {
		wg.Add(1)
		go func(tt struct {
			name     string
			email    string
			password string
			exErr    string
		}) {
			defer wg.Done()

			t.Run(tt.name, func(t *testing.T) {
				_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
					Email:    tt.email,
					Password: tt.password,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.exErr)
			})
		}(tt)
	}

	wg.Wait()
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name     string
		email    string
		password string
		appId    int32
		exErr    string
	}{
		{
			name:     "Login with Empty Password",
			email:    gofakeit.Email(),
			password: "",
			appId:    appId,
			exErr:    "password is required",
		},
		{
			name:     "Login with Empty Email",
			email:    "",
			password: randomFakePassword(),
			appId:    appId,
			exErr:    "email is required",
		},
		{
			name:     "Login with Both Empty Email and Password",
			email:    "",
			password: "",
			appId:    appId,
			exErr:    "email is required",
		},
		{
			name:     "Login with Non-Matching Password",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			appId:    appId,
			exErr:    "invalid email or password",
		},
		{
			name:     "Login without AppId",
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			appId:    emptyAppId,
			exErr:    "app_id is required",
		},
	}

	var wg sync.WaitGroup

	for _, tt := range tests {
		wg.Add(1)
		go func(tt struct {
			name     string
			email    string
			password string
			appId    int32
			exErr    string
		}) {
			defer wg.Done()

			t.Run(tt.name, func(t *testing.T) {
				_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
					Email:    gofakeit.Email(),
					Password: randomFakePassword(),
				})
				require.NoError(t, err)

				_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
					Email:    tt.email,
					Password: tt.password,
					AppId:    tt.appId,
				})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.exErr)
			})
		}(tt)
	}

	wg.Wait()
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, paaDefaultLen)
}
