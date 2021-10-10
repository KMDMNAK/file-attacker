package main

import (
	"testing"
)

func TestAttacker_NextPassword_Length0(t *testing.T) {
	a := NewAttacker(0, LOWERALPHABETS, nil)
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
	a = NewAttacker(0, LOWERALPHABETS, nil)
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

func TestAttacker_NextPassword_Length0_with_initial(t *testing.T) {
	initial := []byte("aaa")
	a := NewAttacker(0, LOWERALPHABETS, initial)
	if a.currentPassword[0] != initial[0] {
		t.Errorf("%d should be %d", a.currentPassword[0], initial[0])
	}
	if a.currentPasswordTable[0] != 0 {
		t.Errorf("%d should be %d", a.currentPasswordTable[0], 0)
	}
	pb, err := a.NextPassword()
	p := string(pb)
	if err != nil {
		t.Error(err.Error())
	}
	// consider that isFirst is true
	if p != "aaa" {
		t.Errorf("%s should be %s", p, "baa")
	}
	pb, err = a.NextPassword()
	p = string(pb)
	if err != nil {
		t.Error(err.Error())
	}
	if p != "baa" {
		t.Errorf("%s should be %s", p, "caa")
	}
	a = NewAttacker(0, LOWERALPHABETS, initial)
	for i := 0; i < 27; i++ {
		pb, err = a.NextPassword()
		p = string(pb)
		if err != nil {
			t.Error(err.Error())
		}
	}
	if p != "bba" {
		t.Errorf("%s should be %s", p, "aba")
	}
}

func TestAttacker_NextPassword_Length(t *testing.T) {
	a := NewAttacker(3, LOWERALPHABETS, nil)
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
		// TODO somehow failed
		// {
		// 	args:    args{"testdata/password-pwin1.zip", 5, LOWERALPHABETSANDNUMBERS},
		// 	wantErr: false,
		// 	want:    "pwin1",
		// 	name:    "(success) password pwin1 no limit",
		// },
	}
	for _, tt := range tests {
		pw, err := LockOnFile(tt.args.fp, uint16(tt.args.length), 3, tt.args.pwCharactors, "")
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
