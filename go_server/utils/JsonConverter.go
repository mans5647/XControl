package utils

import (
	"encoding/json"
)

func ToJson(obj any) string {

	res, err := json.Marshal(obj);
	if (err != nil) {
		return ""
	} 

	return string(res);
}

func FromJson(obj_out any, data * string) bool {

	err := json.Unmarshal([]byte(*data), obj_out)
	return err == nil;
}