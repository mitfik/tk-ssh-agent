package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// hasArg - Check if an argument was passed (useful for strings which are non-nilable)
func hasArg(args []string, argument string) bool {
	for _, v := range args {
		if strings.Replace(v, "-", "", -1) == argument {
			return true
		}
	}
	return false
}

func defaultSockPath() string {
	defaultPath := "/tmp/tk-ssh-auth.sock"
	sockName := "tk-ssh-auth.sock"

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("TMPDIR"), sockName)

	case "linux":
		// Not everyone actually follows XDG spec
		xdgDir := os.Getenv("XDG_RUNTIME_DIR")
		if xdgDir == "" {
			return defaultPath
		}
		return filepath.Join(xdgDir, sockName)

	default:
		return defaultPath
	}
}

func main() {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}

	agentCommand := flag.NewFlagSet("agent", flag.ExitOnError)
	agentOutputShell := agentCommand.String("shell", "bash", "(bash|fish)")
	agentQuiet := agentCommand.Bool("quiet", false, "Dont output shell command for config")
	agentBackend := agentCommand.String("proxy", "", "Proxy unknown identities to agent unix domain socket")
	agentSockPath := agentCommand.String("socket", defaultSockPath(), "Path to unix domain socket")
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

	configCommand := flag.NewFlagSet("config", flag.ExitOnError)
	configConfigPath := configCommand.String("config",
		path.Join(usr.HomeDir, ".config", "tk-ssh.json"),
		"/path/to/conf.json")
	configProxy := configCommand.String("proxy",
		"",
		"Set default proxy")

	printDefaults := func() {
		fmt.Println(fmt.Sprintf("Usage: \"%s agent\" or \"%s enroll\"", os.Args[0], os.Args[0]))

		fmt.Println("\nUsage of enroll:")
		enrollCommand.PrintDefaults()

		fmt.Println("\nUsage of agent:")
		agentCommand.PrintDefaults()

		fmt.Println("\nUsage of config:")
		configCommand.PrintDefaults()

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
	case "config":
		configCommand.Parse(os.Args[2:])
	default:
		printDefaults()
		os.Exit(1)
	}

	if agentCommand.Parsed() {

		configExtra := ReadConfigExtra(*agentConfigPath)

		proxyBackend := ""
		if hasKey(configExtra, "proxy") {
			proxyBackend = configExtra["proxy"].(string)
		}
		if *agentBackend != "" {
			proxyBackend = *agentBackend
		}

		AgentMain(*agentQuiet, *agentOutputShell, *agentConfigPath, *agentSockPath, proxyBackend)
	} else if enrollCommand.Parsed() {
		if *enrollEmail == "" {
			enrollCommand.PrintDefaults()
			os.Exit(1)
		}

		EnrollMain(*enrollEmail, *enrollRpURLFlag, *enrollConfigPath)
	} else if configCommand.Parsed() {

		if !hasArg(os.Args[2:], "proxy") {
			configProxy = nil
		}

		err := ConfigMain(*configConfigPath, configProxy)
		if err != nil {
			panic(err)
		}
		fmt.Println("Updated configuration!")
	}
}
