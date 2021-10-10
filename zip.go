package main

import (
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"

	"github.com/KMDMNAK/zip"
	"github.com/pkg/errors"
)

var (
	NoEncryptedErr = errors.New("")
)

type file struct {
	encryptionHeader    []byte
	generalPurposeFlags uint16
	crc32               uint32
	lastModFileTime     uint16
	offset              int64
}

func (f *file) getEncryptionHeader(r io.ReadSeekCloser) error {
	_, err := r.Seek(f.offset, 0)
	if err != nil {
		return err
	}
	_, err = r.Read(f.encryptionHeader[:])
	return err
}

func CreateZipFile(fp string) (passwordValidator, error) {
	zr, err := zip.OpenReader(fp)
	if err != nil {
		return nil, err
	}
	r, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	files := make([]*file, len(zr.File))
	for i, f := range zr.File {
		if !f.IsEncrypted() {
			return nil, NoEncryptedErr
		}
		offset, err := f.DataOffset()
		if err != nil {
			return nil, err
		}
		ff := file{
			encryptionHeader:    make([]byte, 12),
			offset:              offset,
			crc32:               f.CRC32,
			lastModFileTime:     f.ModifiedTime,
			generalPurposeFlags: f.Flags,
		}
		err = ff.getEncryptionHeader(r)
		if err != nil {
			return nil, err
		}
		files[i] = &ff
	}
	return passwordValidator(files), nil
}

type passwordValidator []*file

func (pv passwordValidator) Validate(passphare []byte) bool {
	zc := ZipCrypto{
		password: passphare,
	}
	for _, f := range pv {
		zc.init()
		err := zc.CheckPasswordVerification(f)
		if err != nil {
			return false
		}
	}
	return true
}

type ZipCrypto struct {
	password []byte
	Keys     [3]uint32
}

func (z *ZipCrypto) init() {
	z.Keys[0] = 0x12345678
	z.Keys[1] = 0x23456789
	z.Keys[2] = 0x34567890

	for i := 0; i < len(z.password); i++ {
		z.updateKeys(z.password[i])
	}
}

func (z *ZipCrypto) updateKeys(byteValue byte) {
	z.Keys[0] = crc32update(z.Keys[0], byteValue)
	z.Keys[1] = (z.Keys[1]+z.Keys[0]&0xff)*0x8088405 + 1
	z.Keys[2] = crc32update(z.Keys[2], (byte)(z.Keys[1]>>24))
}

func (z *ZipCrypto) magicByte() byte {
	var t uint32 = z.Keys[2] | 2
	return byte((t * (t ^ 1)) >> 8)
}

func (z *ZipCrypto) Decrypt(chiper []byte) []byte {
	length := len(chiper)
	plain := make([]byte, length)
	for i, c := range chiper {
		v := c ^ z.magicByte()
		z.updateKeys(v)
		plain[i] = v
	}
	return plain
}

func (z *ZipCrypto) CheckPasswordVerification(f *file) error {
	decryptedHeader := z.Decrypt(f.encryptionHeader)
	z.init()
	if f.generalPurposeFlags&0x8 > 0 {
		if (f.lastModFileTime>>8)&0xff != uint16(decryptedHeader[11]) {
			return errors.Errorf("Invalid Password :: Flags: %d, DecryptedHeader: %s, ModifiedTime: %d", f.generalPurposeFlags, hex.EncodeToString(decryptedHeader), (f.lastModFileTime>>8)&0xff)
		}
	} else if (f.crc32>>24)&0xff != uint32(decryptedHeader[11]) {
		return errors.Errorf("Invalid Password :: Flags: %d, DecryptedHeader: %s, CRC32: %d", f.generalPurposeFlags, hex.EncodeToString(decryptedHeader), (f.crc32>>24)&0xff)
	}
	return nil
}

func crc32update(pCrc32 uint32, bval byte) uint32 {
	return crc32.IEEETable[(pCrc32^uint32(bval))&0xff] ^ (pCrc32 >> 8)
}
