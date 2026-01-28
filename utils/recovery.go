package utils

import (
	"log"
	"runtime/debug"
)

// SafeGo starts a goroutine with panic recovery
func SafeGo(fn func(), name string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[CRITICAL] Panic in %s: %v\n%s", name, r, string(debug.Stack()))
				// Optionally restart the routine or metrics
			}
		}()
		fn()
	}()
}
