package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"cysec/internal/model"
	"cysec/internal/store"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = errors.New("unauthorized")

// ErrRateLimited 登录失败次数达到上限（防口令爆破）
var ErrRateLimited = errors.New("rate limited")

type Auth struct {
	store     *store.Store
	ttlHours  int
	adminUser string
	adminPass string
	throttle  *loginThrottle
}

func New(st *store.Store, adminUser, adminPass string, ttlHours int) *Auth {
	return &Auth{store: st, ttlHours: ttlHours, adminUser: adminUser, adminPass: adminPass, throttle: newLoginThrottle(10*time.Minute, 8)}
}

// loginThrottle 登录失败滑动窗口限流：按来源 IP 与用户名分别计数，窗口内失败
// 达上限后拒绝后续尝试。内存实现（重启清零、单机部署），登录成功即清零该维度计数。
type loginThrottle struct {
	mu        sync.Mutex
	window    time.Duration
	maxFails  int
	ipFails   map[string][]time.Time
	userFails map[string][]time.Time
}

func newLoginThrottle(window time.Duration, maxFails int) *loginThrottle {
	return &loginThrottle{window: window, maxFails: maxFails, ipFails: map[string][]time.Time{}, userFails: map[string][]time.Time{}}
}

// pruneInWindow 剔除窗口外时间戳并返回剩余数量
func pruneInWindow(ts []time.Time, window time.Duration) []time.Time {
	cutoff := time.Now().Add(-window)
	for i, t := range ts {
		if t.After(cutoff) {
			return ts[i:]
		}
	}
	return nil
}

func (t *loginThrottle) blocked(ip, user string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(pruneInWindow(t.ipFails[ip], t.window)) >= t.maxFails ||
		len(pruneInWindow(t.userFails[user], t.window)) >= t.maxFails
}

func (t *loginThrottle) recordFailure(ip, user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.ipFails[ip] = append(pruneInWindow(t.ipFails[ip], t.window), now)
	t.userFails[user] = append(pruneInWindow(t.userFails[user], t.window), now)
}

func (t *loginThrottle) reset(ip, user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.ipFails, ip)
	delete(t.userFails, user)
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

// WarnDefaultPassword 启动安全自检：管理员仍使用引导默认口令时输出告警
// （默认口令已在 README 公开，未修改的实例可被任意登录接管）
func (a *Auth) WarnDefaultPassword() {
	u, err := a.store.GetUser(a.adminUser)
	if err != nil {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(a.adminPass)) == nil {
		log.Printf("[安全告警] 管理员 %s 仍在使用默认口令（README 公开，存在被接管风险），请登录后立即修改密码", a.adminUser)
	}
}

// Login 校验用户名口令并签发会话令牌；连续失败触发限流（ErrRateLimited）
func (a *Auth) Login(clientIP, username, password string) (string, error) {
	if a.throttle.blocked(clientIP, username) {
		return "", ErrRateLimited
	}
	u, err := a.store.GetUser(username)
	if err != nil {
		a.throttle.recordFailure(clientIP, username)
		return "", ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		a.throttle.recordFailure(clientIP, username)
		return "", ErrUnauthorized
	}
	a.throttle.reset(clientIP, username)
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
		if token == "" {
			// SSE 的 EventSource 无法携带自定义请求头，允许 ?token= 查询参数认证
			token = c.Query("token")
		}
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
