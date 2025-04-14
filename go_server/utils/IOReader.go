package utils

import (
	"io"
)


func GetRequestBodyAsString(input * io.ReadCloser, out * string) bool {

	bytes, err := io.ReadAll(*input);
	(*out) = string(bytes);
	return err == nil;
}