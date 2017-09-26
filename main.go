package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
)

func main() {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}

	agentCommand := flag.NewFlagSet("agent", flag.ExitOnError)
	agentOutputShell := agentCommand.String("shell", "bash", "(bash|fish)")
	agentQuiet := agentCommand.Bool("quiet", false, "Dont output shell command for config")
	agentSockPath := agentCommand.String("socket", "/tmp/tk-ssh-auth.sock", "Path to unix domain socket")
	agentConfigPath := agentCommand.String("config",
		path.Join(usr.HomeDir, ".config", "tk-ssh.json"),
		"/path/to/conf.json")

	enrollCommand := flag.NewFlagSet("enroll", flag.ExitOnError)
	enrollConfigPath := enrollCommand.String("config",
		path.Join(usr.HomeDir, ".config", "tk-ssh.json"),
		"/path/to/conf.json")
	enrollRpURLFlag := enrollCommand.String("rpURL",
		"https://ssh.trustedkey.com",
		"Relying party URL")
	enrollEmail := enrollCommand.String("email",
		"",
		"Email address (required)")

	printDefaults := func() {
		fmt.Println(fmt.Sprintf("Usage: \"%s agent\" or \"%s enroll\"", os.Args[0], os.Args[0]))

		fmt.Println("\nUsage of enroll:")
		enrollCommand.PrintDefaults()

		fmt.Println("\nUsage of agent:")
		agentCommand.PrintDefaults()

		flag.PrintDefaults()
	}

	if len(os.Args) <= 1 {
		printDefaults()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "enroll":
		enrollCommand.Parse(os.Args[2:])
	case "agent":
		agentCommand.Parse(os.Args[2:])
	default:
		printDefaults()
		os.Exit(1)
	}

	if agentCommand.Parsed() {
		AgentMain(*agentQuiet, *agentOutputShell, *agentConfigPath, *agentSockPath)
	}

	if enrollCommand.Parsed() {
		if *enrollEmail == "" {
			enrollCommand.PrintDefaults()
			os.Exit(1)
		}

		EnrollMain(*enrollEmail, *enrollRpURLFlag, *enrollConfigPath)
	}
}
