package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type charactorMode uint8

var (
	LOWERALPHABETS                   = "abcdefghijklmnopqrstuvwxyz"
	LOWERALPHABETSANDNUMBERS         = "abcdefghijklmnopqrstuvwxyz1234567890"
	LOWERALPHABETSANDNUMBERSANDCOLON = "abcdefghijklmnopqrstuvwxyz1234567890."
)

func (cm charactorMode) CharactorStrings() string {
	switch cm {
	case 0:
		{
			return LOWERALPHABETSANDNUMBERS
		}
	case 1:
		{
			return LOWERALPHABETSANDNUMBERSANDCOLON
		}
	default:
		{
			return LOWERALPHABETS
		}
	}
}

func setAttackCommand(rootCmd *cobra.Command) {
	// var filePath string
	var plen uint16
	var fp string
	var mode uint16
	var routineLimit int64
	var initialPassword string
	var sleepCount uint64
	c := &cobra.Command{
		Use: "attack",
		Run: func(cmd *cobra.Command, args []string) {
			if len(fp) == 0 {
				fmt.Println("set file path")
				return
			}
			ps, err := LockOnFile(fp, uint16(plen), routineLimit, charactorMode(mode).CharactorStrings(), initialPassword, sleepCount)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println("password candidates are")
				fmt.Println(ps)
			}
		},
	}
	// c.Flags().Uint8("pl", plen, "password-length")
	c.PersistentFlags().StringVarP(&fp, "filepath", "f", "", "filepath")
	c.PersistentFlags().Uint16VarP(&plen, "pwl", "l", 0, "password length")
	c.PersistentFlags().Uint16VarP(&mode, "mode", "m", 0, "target charactor mode")
	c.PersistentFlags().Int64VarP(&routineLimit, "routine", "r", 3, "go routine limit number")
	c.PersistentFlags().StringVarP(&initialPassword, "initial", "i", "", "initial password string")
	c.PersistentFlags().Uint64VarP(&sleepCount, "sleep", "s", 0, "count for sleep")
	rootCmd.AddCommand(c)
}

func createRootCommand() *cobra.Command {
	rootCmd := cobra.Command{
		Use: "fa",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("file-attacker...")
		},
	}
	setAttackCommand(&rootCmd)
	return &rootCmd
}

func main() {
	rootCmd := createRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
