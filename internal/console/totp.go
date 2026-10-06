package console

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP（RFC 6238）实现。
//
// 为什么自己写而不是引库：整个项目只依赖标准库 + yaml.v3，TOTP 的算法本身
// 就是 HMAC-SHA1 + 动态截断，二十行能写完且可测；为了它引一个第三方依赖
// 不值得（供应链面越大，WAF 这种东西越不该多带东西）。
//
// 参数取认证器 App 的通用默认值（SHA1 / 6 位 / 30 秒），并接受前后各一个
// 时间窗 —— 手机与服务端的时钟通常有几十秒偏差，只认当前窗口会让用户
// 反复输错然后来找你。

const (
	totpPeriod = 30 * time.Second
	totpDigits = 6
)

// totpSecretBytes 是密钥长度。20 字节 = 160 bit，与 SHA1 的输出等长，
// 这是 RFC 6238 推荐值，也是各家认证器 App 的默认。
const totpSecretBytes = 20

// generateTOTPSecret 生成 base32（无填充）密钥。
func generateTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// totpURI 生成 otpauth:// URI（认证器 App 扫这个或手工填密钥）。
func totpURI(issuer, account, secret string) string {
	if issuer == "" {
		issuer = "donothack"
	}
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCodeAt 计算某个时刻的验证码。
func totpCodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / int64(totpPeriod.Seconds()))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// 动态截断（RFC 4226 §5.3）
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod), nil
}

// verifyTOTP 校验验证码，窗口为前后各一步。
//
// 用 subtle.ConstantTimeCompare 而不是 ==：验证码比较也是密码比较，
// 虽然 6 位数字的时序攻击实际意义不大，但这里没有理由不写成常量时间。
func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if code == "" || len(secret) == 0 {
		return false
	}
	for _, offset := range []time.Duration{0, -totpPeriod, totpPeriod} {
		want, err := totpCodeAt(secret, now.Add(offset))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// decodeTOTPSecret 解析 base32 密钥（容忍小写、空格、带填充与不带填充两种写法）。
func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("密钥为空")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
