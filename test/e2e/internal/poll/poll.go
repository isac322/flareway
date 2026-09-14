/*
Copyright 2026 Byeonghoon Yoo.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package poll provides context-bounded reconciliation polling without sleeps.
package poll

import (
	"context"
	"fmt"
	"time"
)

// Until evaluates check immediately and then at interval until it succeeds.
// A non-nil check error stops polling because deterministic API failures should
// not be hidden as propagation delay.
func Until(ctx context.Context, interval time.Duration, check func(context.Context) (bool, error)) (time.Duration, error) {
	if interval <= 0 {
		return 0, fmt.Errorf("poll interval must be positive")
	}
	started := time.Now()
	for {
		done, err := check(ctx)
		if err != nil {
			return time.Since(started), err
		}
		if done {
			return time.Since(started), nil
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return time.Since(started), ctx.Err()
		case <-timer.C:
		}
	}
}
