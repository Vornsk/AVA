package masking

import "testing"

func TestMask(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"benign unchanged", "user=admin", "user=admin"},
		{"key password", "password=secret", "password=***"},
		{"key token", "token=abcdef", "token=***"},
		{"key session", "session=abc123", "session=***"},
		{"key csrf", "csrf=xyz", "csrf=***"},
		{"key authorization", "authorization=xyztoken", "authorization=***"},
		{"pattern RRN in value", "x=900101-1234567", "x=******-*******"},
		{"pattern card (key not in kv-list)", "card=1234-5678-9012-3456", "card=****-****-****-****"},
		{"key rrn wins over value", "rrn=900101-1234567", "rrn=***"},
		{"JWT", "eyJhbGci.eyJzdWIi.SflKxwRJ", "***JWT***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Mask(c.in); got != c.want {
				t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMaskMixedURL(t *testing.T) {
	in := "https://h/get?user=admin&password=pw&token=tk"
	got := Mask(in)
	if got != "https://h/get?user=admin&password=***&token=***" {
		t.Errorf("mixed URL mask = %q", got)
	}
}
