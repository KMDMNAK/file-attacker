package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func setAttackCommand(rootCmd *cobra.Command) {
	// var filePath string
	c := &cobra.Command{
		Use: "attack",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("file-attacker...")
		},
	}
	rootCmd.AddCommand(c)
}
func GetCommand() *cobra.Command {
	rootCmd := cobra.Command{
		Use: "fa",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("file-attacker...")
		},
	}
	rootCmd.AddCommand()
	return &rootCmd
}

func main() {
	rootCmd := GetCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
