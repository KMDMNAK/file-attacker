package main

import (
	"testing"
)

func TestAttacker_NextPassword_Length0(t *testing.T) {
	a := NewAttacker(0, LOWERALPHABETS)
	pb, err := a.NextPassword()
	p := string(pb)
	if err != nil {
		t.Error(err.Error())
	}
	if p != "a" {
		t.Errorf("%s should be %s", p, "a")
	}
	pb, err = a.NextPassword()
	p = string(pb)
	if err != nil {
		t.Error(err.Error())
	}
	if p != "b" {
		t.Errorf("%s should be %s", p, "b")
	}
	a = NewAttacker(0, LOWERALPHABETS)
	for i := 0; i < 27; i++ {
		pb, err = a.NextPassword()
		p = string(pb)
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
	if string(p) != "aaa" {
		t.Errorf("%s should be %s", p, "aaa")
	}
}

func TestLockOnFile(t *testing.T) {
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
			args:    args{"testdata/password-ab8.zip", 3, LOWERALPHABETSANDNUMBERS},
			want:    "ab8",
			wantErr: false,
			name:    "(success) password ab8",
		}, {
			args:    args{"testdata/password-ab8.zip", 3, LOWERALPHABETS},
			wantErr: true,
			name:    "(fail) password ab8",
		},
		{
			args:    args{"testdata/password-erc8.zip", 4, LOWERALPHABETS},
			wantErr: true,
			name:    "(fail) password erc8",
		}, {
			args:    args{"testdata/password-erc8.zip", 0, LOWERALPHABETSANDNUMBERS},
			wantErr: false,
			want:    "erc8",
			name:    "(success) password erc8",
		}, {
			args:    args{"testdata/password-abcde.zip", 0, LOWERALPHABETSANDNUMBERS},
			wantErr: false,
			want:    "abcde",
			name:    "(success) password erc8 no limit",
		},
	}
	for _, tt := range tests {
		pw, err := LockOnFile(tt.args.fp, uint16(tt.args.length), tt.args.pwCharactors)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("name :%s\n%s", tt.name, err.Error())
			}
			continue
		}
		if pw != tt.want {
			t.Errorf("name :%s\nexpect :%s \nactual :%s", tt.name, tt.want, pw)
		}
	}
}
