package main

import (
	"testing"
)

/**
local file header signature     4 bytes  (0x04034b50)
version needed to extract       2 bytes
general purpose bit flag        2 bytes
compression method              2 bytes
last mod file time              2 bytes
last mod file date              2 bytes
crc-32                          4 bytes
compressed size                 4 bytes
uncompressed size               4 bytes
file name length                2 bytes
extra field length              2 bytes
*/

func TestGetFileInfo(t *testing.T) {
	type args struct {
		fp string
	}
	tests := []struct {
		args args
		name string
		want file
	}{
		{
			name: "password-ab8.zip",
			args: args{fp: "testdata/password-ab8.zip"},
			want: file{
				crc32: 3453873229,
			},
		}, {
			name: "password-abc.zip",
			args: args{fp: "testdata/password-abc.zip"},
			want: file{
				crc32: 1544550971,
			},
		}, {
			name: "password-pwin1.zip",
			args: args{fp: "testdata/password-pwin1.zip"},
			want: file{
				crc32: 1544550971,
			},
		},
	}
	for _, tt := range tests {
		t.Logf("Test Name :%s", tt.name)
		files, err := CreateZipFile(tt.args.fp)
		if err != nil {
			t.Errorf(err.Error())
		}
		if len(files) < 1 {
			t.Errorf("no filesS")
		}
	}
}
