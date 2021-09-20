package main

import (
	// "archive/zip"
	"errors"

	// "github.com/alexmullins/zip"
	// "github.com/yeka/zip"
	"github.com/mzky/zip"
)

var (
	LOWERALPHABETS           = "abcdefghijklmnopqrstuvwxyz"
	LOWERALPHABETSANDNUMBERS = "abcdefghijklmnopqrstuvwxyz1234567890"
)

func LockOnFile(filePath string, passwordLength uint8, pwCharactors string) (string, error) {
	tf, err := NewTargetFile(filePath)
	if err != nil {
		return "", err
	}
	if !tf.isEncrypted() {
		return "", errors.New("this file is not encrypted")
	}
	attacker := NewAttacker(passwordLength, pwCharactors)
	for {
		p, err := attacker.NextPassword()
		if err != nil {
			return "", err
		}
		tf.oneFile.SetPassword(p)
		_, err = tf.oneFile.Open()
		if err == nil {
			return p, nil
		}
	}
}

func NewAttacker(length uint8, targetCharactors string) *Attacker {
	a := Attacker{
		TargetCharactors:        []byte(targetCharactors),
		length:                  length,
		isVarLength:             false,
		targetCharactorMaxIndex: uint8(len(targetCharactors)) - 1,
		isFirst:                 true,
	}
	a.preparePassword()
	return &a
}

type Attacker struct {
	TargetCharactors        []byte
	targetCharactorMaxIndex uint8
	currentPassword         []byte
	currentPasswordTable    []uint8
	isVarLength             bool
	length                  uint8
	isFirst                 bool
}

func (a *Attacker) addLength() {
	a.currentPassword = append(a.currentPassword, a.TargetCharactors[0])
	a.currentPasswordTable = make([]uint8, len(a.currentPasswordTable)+1, len(a.currentPasswordTable)+1)
}

func (a *Attacker) NextPassword() (string, error) {
	addLengthFlag := false
	for i := 0; i < len(a.currentPasswordTable); i++ {
		if a.isFirst {
			a.isFirst = false
			break
		}
		if a.currentPasswordTable[i] < a.targetCharactorMaxIndex {
			a.currentPasswordTable[i]++
			a.currentPassword[i] = a.TargetCharactors[a.currentPasswordTable[i]]
			break
		} else {
			a.currentPasswordTable[i] = 0
			a.currentPassword[i] = a.TargetCharactors[a.currentPasswordTable[0]]
			if i == len(a.currentPasswordTable)-1 {
				addLengthFlag = true
			}
		}
	}
	if addLengthFlag {
		if !a.isVarLength {
			return "", errors.New("no password was found")
		}
		a.addLength()
	}
	return string(a.currentPassword), nil
}

func (a *Attacker) preparePassword() {
	if a.length == 0 {
		a.isVarLength = true
		a.currentPassword = []byte{a.TargetCharactors[0]}
		a.currentPasswordTable = []uint8{0}
	} else {
		a.currentPassword = make([]byte, a.length, a.length)
		for i := 0; i < int(a.length); i++ {
			a.currentPassword[i] = a.TargetCharactors[0]
		}
		a.currentPasswordTable = make([]uint8, a.length, a.length)
	}
}

func NewTargetFile(filePath string) (*targetFile, error) {
	fp, err := getFilePath(filePath)
	if err != nil {
		return nil, err
	}
	zr, err := zip.OpenReader(fp)
	if err != nil {
		return nil, err
	}
	tf := targetFile{zr: zr}
	tf.oneFile = tf.zr.File[0]
	return &tf, err
}

type targetFile struct {
	zr      *zip.ReadCloser
	oneFile *zip.File
}

func (tf *targetFile) isEncrypted() bool {
	if tf.zr == nil {
		return false
	}
	if len(tf.zr.File) == 0 {
		return false
	}
	return tf.oneFile.IsEncrypted()
}
