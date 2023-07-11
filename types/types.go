// Copyright 2016-2017 Hyperchain Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package types defines all structs used by external modules.
package types

import (
	"fmt"
)

// ----------- ServiceState related structs-----------------

// ServiceState indicates the returned info from chain db.
type ServiceState struct {
	MetaState *MetaState
	Epoch     uint64
}

// MetaState is the basic info for block.
type MetaState struct {
	Height uint64
	Digest string
}

// CommonCheckpointState is the basic info for checkpoint.
type CheckpointState struct {
	Meta     MetaState
	IsConfig bool
}

// String implement the Stringer interface.
func (state *ServiceState) String() string {
	var ms string
	if state.MetaState == nil {
		ms = "NIL"
	} else {
		ms = fmt.Sprintf("height: %d, digest: %s", state.MetaState.Height,
			state.MetaState.Digest)
	}
	s := fmt.Sprintf("epoch: %d, MetaState: %s", state.Epoch, ms)
	if state.MetaState == nil {
		return s
	}
	return s
}

// ----------- Router related structs-----------------

// Router is the router info.
type Router struct {
	Peers []*Peer
}

// String implement the Stringer interface.
func (r *Router) String() string {
	if r == nil {
		return "NIL ROUTER"
	}
	s := "Router:"
	for _, p := range r.Peers {
		s += fmt.Sprintf("\n%s", p)
	}
	return s
}

// Peer is the peer info.
type Peer struct {
	ID       uint64
	Hostname string
	Hash     string
}

// String implement the Stringer interface.
func (p *Peer) String() string {
	if p == nil {
		return "NIL PEER"
	}
	return fmt.Sprintf("ID: %d, Hostname: %s, Hash: %s", p.ID, p.Hostname, p.Hash)
}

// ConfChange is the config change event.
type ConfChange struct {
	Router *Router
}

// ConfState is the config state structure.
type ConfState struct {
	QuorumRouter *Router
}

// ----------- Filter system related structs-----------------

// InformType indicates different event types.
type InformType int32

const (
	// InformTypeFilterFinishRecovery indicates recovery finished event.
	InformTypeFilterFinishRecovery InformType = 0

	// InformTypeFilterFinishViewChange indicates vc finished event.
	InformTypeFilterFinishViewChange InformType = 1

	// InformTypeFilterFinishConfigChange indicates config change finished event.
	InformTypeFilterFinishConfigChange InformType = 2

	// InformTypeFilterFinishStateUpdate indicates state update finished event.
	InformTypeFilterFinishStateUpdate InformType = 3

	// InformTypeFilterPoolFull indicates pool full event.
	InformTypeFilterPoolFull InformType = 4

	// InformTypeFilterStableCheckpoint indicates stable checkpoint event.
	InformTypeFilterStableCheckpoint InformType = 5
)
