package async

import (
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/signer"
)

// Callback is a closure encapsulating the neccesary info to
// retry an Asyncronous sign call.
type Callback func() (cert []byte, err error)

// RetryError is an signer error encapsulating callback information to retry a sign.
type RetryError struct {
	retry    Callback
	deadline time.Time
}

// NewRetryError creates a new `RetryError` error.
func NewRetryError(retry Callback, deadline time.Time) *RetryError {
	return &RetryError{retry, deadline}
}

// Retry the sign request encapsulated in the callback.
func (r *RetryError) Retry() (cert []byte, err error) {
	if time.Now().After(r.deadline) {
		return nil, errors.New("asynchronous callback has expired")
	}
	return r.retry()
}

func (r *RetryError) Error() string {
	return fmt.Sprintf("asyncronous callback expiring at %v", r.deadline)
}

// SynchronousSign is a helper function that creates a synchronous sign call by
// repeatedly calling `Retry()` whenever a `RetryError` is encountered.
func SynchronousSign(s signer.Signer, req signer.SignRequest, deadline time.Time) (cert []byte, err error) {
	cert, err = s.Sign(req)
	r, ok := err.(*RetryError)
	for ; ok; r, ok = err.(*RetryError) {
		cert, err = r.Retry()
	}
	return
}
