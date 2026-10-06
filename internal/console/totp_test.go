package console

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 附录 B 的官方测试向量（SHA1 / 8 位）。
//
// 用官方向量而不是自己算一遍再对一遍：自己算的期望值只能证明"实现没变"，
// 证明不了"实现是对的"。这里的密钥是 ASCII "12345678901234567890"。
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// RFC 用的是 8 位码，本实现固定 6 位，所以取官方 8 位结果的后 6 位比较。
	secret := base32NoPad([]byte("12345678901234567890"))
	cases := []struct {
		unix int64
		want string // 官方 8 位码
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got, err := totpCodeAt(secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("计算失败：%v", err)
		}
		if want := c.want[len(c.want)-6:]; got != want {
			t.Errorf("t=%d：得到 %s，期望 %s", c.unix, got, want)
		}
	}
}

func base32NoPad(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TestGenerateAndVerifyRoundTrip(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Errorf("20 字节密钥的 base32 无填充长度应为 32，实际 %d", len(secret))
	}
	now := time.Unix(1700000000, 0)
	code, err := totpCodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("验证码应为 6 位，实际 %q", code)
	}
	if !verifyTOTP(secret, code, now) {
		t.Error("当前窗口的验证码应当通过")
	}
	// 前后各一个窗口都要接受（手机时钟偏差是常态）
	if !verifyTOTP(secret, code, now.Add(29*time.Second)) {
		t.Error("前一个窗口内的验证码应当接受")
	}
	if !verifyTOTP(secret, code, now.Add(-29*time.Second)) {
		t.Error("后一个窗口内的验证码应当接受")
	}
	// 超过一个窗口就不该接受
	if verifyTOTP(secret, code, now.Add(90*time.Second)) {
		t.Error("超出窗口的验证码不该接受")
	}
	if verifyTOTP(secret, "000000", now.Add(37*time.Second)) {
		t.Error("错误的验证码不该接受")
	}
	if verifyTOTP(secret, "", now) {
		t.Error("空验证码不该接受")
	}
}

func TestTOTPURIContent(t *testing.T) {
	uri := totpURI("donothack", "admin", "ABCDEFGH")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEFGH", "issuer=donothack", "digits=6", "period=30", "algorithm=SHA1"} {
		if !contains(uri, want) {
			t.Errorf("URI 缺少 %q：%s", want, uri)
		}
	}
}

func TestDecodeSecretTolerant(t *testing.T) {
	want, err := decodeTOTPSecret("ABCDEFGH")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"abcdefgh", "ABCD EFGH", "ABCDEFGH=", " abcdefgh "} {
		got, err := decodeTOTPSecret(variant)
		if err != nil {
			t.Errorf("%q 应当能解码：%v", variant, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%q 解出的字节不一致", variant)
		}
	}
	if _, err := decodeTOTPSecret(""); err == nil {
		t.Error("空密钥应当报错")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
