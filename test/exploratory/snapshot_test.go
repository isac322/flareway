//go:build exploratory

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

package exploratory

import (
	"context"
	"fmt"
	"sync"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/isac322/flareway/internal/controller"
	"github.com/isac322/flareway/internal/xds/translator"
)

// snapshotPublisher is an in-memory, explicitly ACK-controlled
// controller.SnapshotPublisher. It records the latest snapshot per Gateway key
// and lets tests drive ACK/NACK state without an Envoy data plane.
type snapshotPublisher struct {
	mu        sync.RWMutex
	snapshots map[string]*cachev3.Snapshot
	versions  map[string]string
	acked     map[string]string
	nacks     map[string]snapshotNACK
}

var _ controller.SnapshotPublisher = (*snapshotPublisher)(nil)

func newSnapshotPublisher() *snapshotPublisher {
	return &snapshotPublisher{
		snapshots: make(map[string]*cachev3.Snapshot),
		versions:  make(map[string]string),
		acked:     make(map[string]string),
		nacks:     make(map[string]snapshotNACK),
	}
}

// Reset drops every published snapshot and ACK/NACK record so a new
// exploration iteration observes no leftover dataplane state.
func (p *snapshotPublisher) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snapshots = make(map[string]*cachev3.Snapshot)
	p.versions = make(map[string]string)
	p.acked = make(map[string]string)
	p.nacks = make(map[string]snapshotNACK)
}

func (p *snapshotPublisher) SetSnapshot(_ context.Context, key string, snapshot *cachev3.Snapshot) error {
	version, err := translator.SnapshotVersion(snapshot)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.versions[key] != version {
		delete(p.nacks, key)
	}
	p.snapshots[key] = snapshot
	p.versions[key] = version
	return nil
}

func (p *snapshotPublisher) ClearSnapshot(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.snapshots, key)
	delete(p.versions, key)
	delete(p.acked, key)
	delete(p.nacks, key)
}

func (p *snapshotPublisher) IsACKed(key, version string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.acked[key] == version
}

func (p *snapshotPublisher) LastNACK(key string) (string, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	nack, ok := p.nacks[key]
	return nack.version, nack.detail, ok
}

type snapshotNACK struct {
	version string
	detail  string
}

// ACK marks the currently published version for key as acknowledged by the
// data plane.
func (p *snapshotPublisher) ACK(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	version := p.versions[key]
	if version == "" {
		return fmt.Errorf("no snapshot has been published for %s", key)
	}
	p.acked[key] = version
	return nil
}

// NACK records a rejection of the currently published version for key.
func (p *snapshotPublisher) NACK(key, detail string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	version := p.versions[key]
	if version == "" {
		return fmt.Errorf("no snapshot has been published for %s", key)
	}
	delete(p.acked, key)
	p.nacks[key] = snapshotNACK{version: version, detail: detail}
	return nil
}

// Version returns the currently published snapshot version for key.
func (p *snapshotPublisher) Version(key string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.versions[key]
}
