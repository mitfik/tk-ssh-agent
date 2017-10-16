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

// ConfigMain ...
func ConfigMain(configPath string, configProxy *string) error {
	jsonData := ReadConfigRaw(configPath)

	var configData map[string]interface{}
	if hasKey(jsonData, "config") {
		configData = jsonData["config"].(map[string]interface{})
	} else {
		configData = make(map[string]interface{})
	}

	if configProxy != nil {
		if *configProxy == "" {
			delete(configData, "proxy")
		} else {
			configData["proxy"] = *configProxy
		}
	}

	jsonData["config"] = configData

	return WriteConfigRaw(configPath, jsonData)
}
