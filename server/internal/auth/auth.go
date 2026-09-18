package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"cysec/internal/model"
	"cysec/internal/store"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = errors.New("unauthorized")

type Auth struct {
	store     *store.Store
	ttlHours  int
	adminUser string
	adminPass string
}

func New(st *store.Store, adminUser, adminPass string, ttlHours int) *Auth {
	return &Auth{store: st, ttlHours: ttlHours, adminUser: adminUser, adminPass: adminPass}
}

// Bootstrap 首次启动创建默认管理员
func (a *Auth) Bootstrap() error {
	n, err := a.store.UserCount()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(a.adminPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.CreateUser(&model.User{Username: a.adminUser, Password: string(hash), Role: "admin"})
}

func (a *Auth) Login(username, password string) (string, error) {
	u, err := a.store.GetUser(username)
	if err != nil {
		return "", ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return "", ErrUnauthorized
	}
	buf := make([]byte, 24)
	rand.Read(buf)
	token := hex.EncodeToString(buf)
	if err := a.store.SaveToken(model.Token{Token: token, Username: username, ExpiresAt: time.Now().Add(time.Duration(a.ttlHours) * time.Hour)}); err != nil {
		return "", err
	}
	return token, nil
}

func (a *Auth) Logout(token string) { a.store.DeleteToken(token) }

// ChangePassword 校验旧密码后改用新密码（bcrypt），并吊销该用户其余会话（当前会话保留）
func (a *Auth) ChangePassword(username, oldPass, newPass, currentToken string) error {
	u, err := a.store.GetUser(username)
	if err != nil {
		return ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(oldPass)) != nil {
		return ErrUnauthorized
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := a.store.UpdateUserPassword(username, string(hash)); err != nil {
		return err
	}
	return a.store.DeleteUserTokensExcept(username, currentToken)
}

func (a *Auth) Verify(token string) (string, error) {
	t, err := a.store.GetToken(token)
	if err != nil || time.Now().After(t.ExpiresAt) {
		return "", ErrUnauthorized
	}
	return t.Username, nil
}

// Middleware Bearer 鉴权 + 角色控制（admin 全权限；auditor 只读+创建任务；viewer 只读）
func (a *Auth) Middleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		token := strings.TrimPrefix(h, "Bearer ")
		username, err := a.Verify(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		u, err := a.store.GetUser(username)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if len(roles) > 0 {
			allowed := false
			for _, r := range roles {
				if u.Role == r {
					allowed = true
					break
				}
			}
			if !allowed {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
		}
		c.Set("username", username)
		c.Set("role", u.Role)
		c.Next()
	}
}
