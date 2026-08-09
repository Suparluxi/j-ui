package problem

import "errors"

type Kind string

const (
	Validation  Kind = "validation"
	NotFound    Kind = "not_found"
	Conflict    Kind = "conflict"
	Unavailable Kind = "unavailable"
)

type Error struct {
	Kind    Kind
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func New(kind Kind, code, message string, cause error) error {
	return &Error{Kind: kind, Code: code, Message: message, Cause: cause}
}

func As(err error) (*Error, bool) {
	var value *Error
	return value, errors.As(err, &value)
}
