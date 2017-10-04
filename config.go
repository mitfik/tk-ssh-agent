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
