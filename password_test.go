package main

import (
	"testing"
)

func TestTargetFile_isEncrypted(t *testing.T) {
	tests := []struct {
		fp   string
		want bool
		name string
	}{
		{"testdata/nopassword.zip", false, "not password locked"},
		{"testdata/password-abc.zip", true, "password locked"},
	}
	for _, tt := range tests {
		tf, err := NewTargetFile(tt.fp)
		if err != nil {
			t.Errorf("Name :%s\n%s", tt.name, err.Error())
		}
		if tt.want != tf.isEncrypted() {
			t.Errorf("Name :%s", tt.name)
		}
	}
}

func sTestTargetFile_IsCorrectPassword(t *testing.T) {
	tests := []struct {
		fp   string
		want bool
		name string
	}{
		{"testdata/nopassword.zip", false, "not password locked"},
		{"testdata/password-abc.zip", true, "password locked"},
	}
	for _, tt := range tests {
		tf, err := NewTargetFile(tt.fp)
		if err != nil {
			t.Errorf("Name :%s\n%s", tt.name, err.Error())
		}
		if tt.want != tf.isEncrypted() {
			t.Errorf("Name :%s", tt.name)
		}
	}
}

func TestTargetFile_SetPassword(t *testing.T) {
	type args struct {
		fp       string
		password string
	}
	tests := []struct {
		args    args
		want    bool
		wantErr bool
		name    string
	}{
		{
			args:    args{"testdata/nopassword.zip", ""},
			wantErr: false,
			name:    "(success) nopassword",
		}, {
			args:    args{"testdata/password-aes-abc.zip", "abc"},
			wantErr: false,
			name:    "(success) password abc",
		}, {
			args:    args{"testdata/password-abc.zip", "abc"},
			wantErr: false,
			name:    "(success) password abc",
		}, {
			args:    args{"testdata/password-abc.zip", "paeifje"},
			wantErr: true,
			name:    "(fail) password abc",
		}, {
			args:    args{"testdata/password-ab8.zip", "ab8"},
			wantErr: false,
			name:    "(success) password ab8",
		}, {
			args:    args{"testdata/password-ab8.zip", "efeaf"},
			wantErr: true,
			name:    "(fail) password ab8",
		},
	}
	for _, tt := range tests {

		tf, err := NewTargetFile(tt.args.fp)
		if err != nil {
			t.Errorf("name :%s\n%s", tt.name, err.Error())
		}
		tf.oneFile.SetPassword(tt.args.password)
		_, err = tf.oneFile.Open()
		if err != nil {
			t.Errorf("name :%s", err.Error())
		}
		if err != nil {
			t.Errorf("name :%s", err.Error())
		}
		// if tt.wantErr {
		// 	t.Errorf("should be error %s", tt.name)
		// 	b := make([]byte, 100, 100)
		// 	n, err := f.Read(b)
		// 	t.Logf("byte num :%d\n err %s", n, err.Error())
		// 	t.Logf("first byte %s", hex.EncodeToString(b[:n]))
		// }
	}
}

func TestAttacker_NextPassword_Length0(t *testing.T) {
	a := NewAttacker(0, LOWERALPHABETS)
	p, err := a.NextPassword()
	if err != nil {
		t.Error(err.Error())
	}
	if p != "a" {
		t.Errorf("%s should be %s", p, "a")
	}
	p, err = a.NextPassword()
	if err != nil {
		t.Error(err.Error())
	}
	if p != "b" {
		t.Errorf("%s should be %s", p, "b")
	}
	a = NewAttacker(0, LOWERALPHABETS)
	for i := 0; i < 27; i++ {
		p, err = a.NextPassword()
		if err != nil {
			t.Error(err.Error())
		}
	}
	if p != "aa" {
		t.Errorf("%s should be %s", p, "aa")
	}
}

func TestAttacker_NextPassword_Length(t *testing.T) {
	a := NewAttacker(3, LOWERALPHABETS)
	p, err := a.NextPassword()
	if err != nil {
		t.Error(err.Error())
	}
	if p != "aaa" {
		t.Errorf("%s should be %s", p, "aaa")
	}
}

func sTestLockOnFile(t *testing.T) {
	type args struct {
		fp           string
		length       uint
		pwCharactors string
	}
	tests := []struct {
		args    args
		want    string
		wantErr bool
		name    string
	}{
		{
			args:    args{"testdata/password-abc.zip", 3, LOWERALPHABETS},
			want:    "abc",
			wantErr: false,
			name:    "(success) password abc",
		}, {
			args:    args{"testdata/password-ab8.zip", 3, LOWERALPHABETSANDNUMBERS},
			want:    "ab8",
			wantErr: false,
			name:    "(success) password ab8",
		}, {
			args:    args{"testdata/password-abc.zip", 2, LOWERALPHABETS},
			wantErr: true,
			name:    "(fail) password abc",
		}, {
			args:    args{"testdata/password-ab8.zip", 3, LOWERALPHABETS},
			wantErr: true,
			name:    "(fail) password ab8",
		},
	}
	for _, tt := range tests {
		p, err := LockOnFile(tt.args.fp, uint8(tt.args.length), tt.args.pwCharactors)
		if err != nil && !tt.wantErr {
			t.Errorf("name :%s\n%s", tt.name, err.Error())
			continue
		}
		if p != tt.want && !tt.wantErr {
			t.Errorf("name :%s\nexpect :%s\nactual :%s", tt.name, tt.want, p)
			continue
		}
	}
}
