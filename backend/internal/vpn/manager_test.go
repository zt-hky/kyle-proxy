package vpn

import (
	"reflect"
	"testing"
)

func TestOTPInputs(t *testing.T) {
	tests := []struct {
		name string
		otp  string
		otp2 string
		want []string
	}{
		{
			name: "empty",
		},
		{
			name: "single token is only sent once",
			otp:  "111111",
			want: []string{"111111"},
		},
		{
			name: "second token overrides reuse",
			otp:  "111111",
			otp2: "222222",
			want: []string{"111111", "222222"},
		},
		{
			name: "combined tokens are split",
			otp:  "111111, 222222\n333333",
			want: []string{"111111", "222222", "333333"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := otpInputs(tt.otp, tt.otp2)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("otpInputs(%q, %q) = %#v, want %#v", tt.otp, tt.otp2, got, tt.want)
			}
		})
	}
}
