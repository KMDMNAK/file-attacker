package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"
)

func LockOnFile(filePath string, passwordLength uint16, routineLimit int64, pwCharactors string, initialPassword string, sleepCount uint64) (string, error) {
	var initialPasswordByte []byte
	if initialPassword == "" {
		initialPasswordByte = nil
	} else {
		initialPasswordByte = []byte(initialPassword)
	}
	attacker := NewAttacker(passwordLength, pwCharactors, initialPasswordByte)
	pv, err := CreateZipFile(filePath)
	if err != nil {
		return "", err
	}
	routineChan := make(chan struct{}, routineLimit)
	pwChan := make(chan string, 1)
	var wg sync.WaitGroup
	var gerr error
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	count := 0
L:
	for {
		if sleepCount != 0 {
			count++
			if sleepCount == uint64(count) {
				count = 0
				time.Sleep(time.Second * 1)
			}
		}
		routineChan <- struct{}{}
		select {
		case pw := <-pwChan:
			wg.Wait()
			return pw, nil
		case <-interrupt:
			break L
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
		if gerr != nil {
			return "", gerr
		}
		// case for interrupt
		fmt.Println("Get interrupt")
		b, err := attacker.NextPassword()
		if err != nil {
			return "", err
		}
		fmt.Printf("next %d", b[:])
		os.Exit(1)
	}
	return "", nil
}

func NewAttacker(length uint16, targetCharactors string, initialPassword []byte) *Attacker {
	a := Attacker{
		TargetCharactors: []byte(targetCharactors),
		PasswordLength:   length,
		isVarLength:      length == 0,
		isFirst:          true,
	}
	a.preparePassword(initialPassword)
	return &a
}

type Attacker struct {
	TargetCharactors     []byte
	PasswordLength       uint16
	currentPassword      []byte
	currentPasswordTable []uint16
	isVarLength          bool
	isFirst              bool
}

func (a Attacker) targetCharactorMaxIndex() uint16 {
	return uint16(len(a.TargetCharactors)) - 1
}

func (a *Attacker) extendLength() {
	a.currentPassword = append(a.currentPassword, a.TargetCharactors[0])
	a.currentPasswordTable = make([]uint16, len(a.currentPasswordTable)+1)
}

func (a *Attacker) NextPassword() ([]byte, error) {
	extendLengthFlag := false
	for i := 0; i < len(a.currentPasswordTable); i++ {
		if a.isFirst {
			a.isFirst = false
			break
		}
		if a.currentPasswordTable[i] < a.targetCharactorMaxIndex() {
			a.currentPasswordTable[i]++
			a.currentPassword[i] = a.TargetCharactors[a.currentPasswordTable[i]]
			break
		} else {
			a.currentPasswordTable[i] = 0
			a.currentPassword[i] = a.TargetCharactors[a.currentPasswordTable[0]]
			if i == len(a.currentPasswordTable)-1 {
				extendLengthFlag = true
			}
		}
	}
	if extendLengthFlag {
		if !a.isVarLength {
			return nil, errors.New("no password was found")
		}
		a.extendLength()
	}
	return a.currentPassword, nil
}

// if no missmatch for given byte on table, return 0
func (a Attacker) getTableIndex(b byte) uint16 {
	for i, c := range a.TargetCharactors {
		if c == b {
			return uint16(i)
		}
	}
	return 0
}

func (a *Attacker) preparePassword(initialPassword []byte) {
	if initialPassword != nil && (a.isVarLength || len(initialPassword) == int(a.PasswordLength)) {
		a.currentPassword = initialPassword
		a.currentPasswordTable = make([]uint16, len(a.currentPassword))
		for ti, p := range a.currentPassword {
			a.currentPasswordTable[ti] = a.getTableIndex(p)
		}
		return
	}
	if a.isVarLength {
		a.currentPasswordTable = []uint16{0}
	} else {
		a.currentPasswordTable = make([]uint16, a.PasswordLength)
	}
	a.currentPassword = make([]byte, len(a.currentPasswordTable))
	for i, ti := range a.currentPasswordTable {
		a.currentPassword[i] = a.TargetCharactors[ti]
	}
}
