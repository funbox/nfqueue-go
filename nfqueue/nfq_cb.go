package nfqueue

import (
	"unsafe"
)

import "C"

/*
Cast argument to Queue* before calling the real callback

Notes:
  - export cannot be done in the same file (nfqueue.go) else it
    fails to build (multiple definitions of C functions)
    See https://github.com/golang/go/issues/3497
    See https://github.com/golang/go/wiki/cgo
  - this cast is caused by the fact that cgo does not support
    exporting structs
    See https://github.com/golang/go/wiki/cgo

This function must _nerver_ be called directly.
*/

//export goCallbackWrapper
func goCallbackWrapper(ptrQ *unsafe.Pointer, ptrNfad *unsafe.Pointer) {
	q := (*Queue)(unsafe.Pointer(ptrQ))
	payload := buildPayload(q.cQh, ptrNfad)
	q.cb(payload)
}