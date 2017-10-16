/*
Copyright 2017, Trusted Key
This file is part of Trusted Key SSH-Agent.

Trusted Key SSH-Agent is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Trusted Key SSH-Agent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Trusted Key SSH-Agent.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
)

// inPath - Check if command is present in $PATH
func inPath(command string) bool {
	paths := strings.Split(os.Getenv("PATH"), ":")

	for _, p := range paths {
		_, err := os.Stat(path.Join(p, command))
		if err == nil {
			return true
		}
	}

	return false
}

func notifyWindows(appID string, msg string, otp string) error {
	body := []byte(fmt.Sprintf("%s \r\nCode: %s", msg, otp))
	cmd := exec.Command("msg.exe", "*")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdin.Write(body)
	stdin.Close()

	return cmd.Run()
}

func notifyLibnotify(appID string, msg string, otp string) error {
	body := fmt.Sprintf("%s \nCode: %s", msg, otp)
	return exec.Command("notify-send", appID, body).Run()
}

func notifyDarwin(appID string, msg string, otp string) error {
	osascript := fmt.Sprintf("display notification \"%s\" with title \"%s\" subtitle \"%s\"", otp, appID, msg)
	return exec.Command("osascript", "-e", osascript).Run()
}

// Notify - Send a desktop notification for OTP
func Notify(otp string) {
	appID := "Trusted Key SSH Agent"
	msg := "Verify SSH Login request on your Trusted Key App"

	printNotification := func() {
		fmt.Println(fmt.Sprintf("%s: %s", msg, otp))
	}

	var cmdError error
	cmdError = nil

	switch runtime.GOOS {
	case "darwin":
		cmdError = notifyDarwin(appID, msg, otp)

	case "windows":
		cmdError = notifyWindows(appID, msg, otp)

	case "linux":

		// Windows Subsystem for Linux lies about being Linux
		if inPath("msg.exe") {
			cmdError = notifyWindows(appID, msg, otp)

		} else {
			// Proper Linux
			cmdError = notifyLibnotify(appID, msg, otp)
		}

	default:
		// Assume libnotify on unsupported platforms
		cmdError = notifyLibnotify(appID, msg, otp)
	}

	if cmdError != nil {
		printNotification()
	}

	return
}
