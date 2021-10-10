package main

import (
	"errors"
	"sync"
)

var (
	CHECKLIMIT               = 5
	LOWERALPHABETS           = "abcdefghijklmnopqrstuvwxyz"
	LOWERALPHABETSANDNUMBERS = "abcdefghijklmnopqrstuvwxyz1234567890"
)

func LockOnFile(filePath string, passwordLength uint16, pwCharactors string) (string, error) {
	attacker := NewAttacker(passwordLength, pwCharactors)
	pv, err := CreateZipFile(filePath)
	if err != nil {
		return "", err
	}
	routineChan := make(chan struct{}, CHECKLIMIT)
	pwChan := make(chan string, 1)
	var wg sync.WaitGroup
	var gerr error
	for {
		routineChan <- struct{}{}
		select {
		case pw := <-pwChan:
			wg.Wait()
			return pw, nil
		default:
		}
		p, err := attacker.NextPassword()
		if err != nil {
			gerr = err
			break
		}
		cp := make([]byte, len(p))
		copy(cp, p)
		wg.Add(1)
		go func(pp []byte) {
			defer wg.Done()
			if pv.Validate(pp) {
				pwChan <- string(pp)
			}
			<-routineChan
		}(cp)
	}
	wg.Wait()
	select {
	case pw := <-pwChan:
		return pw, nil
	default:
		return "", gerr
	}
}

func NewAttacker(length uint16, targetCharactors string) *Attacker {
	a := Attacker{
		TargetCharactors:        []byte(targetCharactors),
		length:                  length,
		isVarLength:             false,
		targetCharactorMaxIndex: uint16(len(targetCharactors)) - 1,
		isFirst:                 true,
	}
	a.preparePassword()
	return &a
}

type Attacker struct {
	TargetCharactors        []byte
	targetCharactorMaxIndex uint16
	currentPassword         []byte
	currentPasswordTable    []uint16
	isVarLength             bool
	length                  uint16
	isFirst                 bool
}

func (a *Attacker) addLength() {
	a.currentPassword = append(a.currentPassword, a.TargetCharactors[0])
	a.currentPasswordTable = make([]uint16, len(a.currentPasswordTable)+1)
}

func (a *Attacker) NextPassword() ([]byte, error) {
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
			return nil, errors.New("no password was found")
		}
		a.addLength()
	}
	return a.currentPassword, nil
}

func (a *Attacker) preparePassword() {
	if a.length == 0 {
		a.isVarLength = true
		a.currentPassword = []byte{a.TargetCharactors[0]}
		a.currentPasswordTable = []uint16{0}
	} else {
		a.currentPassword = make([]byte, a.length)
		for i := 0; i < int(a.length); i++ {
			a.currentPassword[i] = a.TargetCharactors[0]
		}
		a.currentPasswordTable = make([]uint16, a.length)
	}
}
