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

package rbft

import (
	"context"
	"sync"

	"github.com/axiomesh/axiom-bft/common/consensus"
	"github.com/axiomesh/axiom-bft/mempool"
	"github.com/axiomesh/axiom-bft/types"
)

// Node represents a node in a RBFT cluster.
//
//go:generate mockgen -destination ./mock_node.go -package rbft -source ./node.go
type Node[T any, Constraint consensus.TXConstraint[T]] interface {
	// Init a RBFT node state.
	Init() error

	// Start starts a RBFT node instance.
	Start() error

	// Stop performs any necessary termination of the Node.
	Stop() [][]byte

	// Propose proposes requests to RBFT core, requests are ensured to be eventually
	// submitted to all non-fault nodes unless current node crash down.
	Propose(requests *consensus.RequestSet) error

	// Step advances the state machine using the given message.
	Step(ctx context.Context, msg *consensus.ConsensusMessage)

	// Status returns the current node status of the RBFT state machine.
	Status() NodeStatus

	// GetUncommittedTransactions returns uncommitted txs
	GetUncommittedTransactions(maxsize uint64) [][]byte

	// ServiceInbound receives and records modifications from application service.
	ServiceInbound

	External
}

type External interface {
	// GetPendingNonceByAccount will return the latest pending nonce of a given account
	GetPendingNonceByAccount(account string) uint64

	// GetPendingTxByHash will return the tx by tx hash
	GetPendingTxByHash(hash string) []byte
}

// ServiceInbound receives and records modifications from application service which includes two events:
//  1. ReportExecuted is invoked after application service has actually height a batch.
//  2. ReportStateUpdated is invoked after application service finished stateUpdate which must be
//     triggered by RBFT core before.
//
// ServiceInbound is corresponding to External.ServiceOutbound.
type ServiceInbound interface {
	// ReportExecuted reports to RBFT core that application service has finished height one batch with
	// current height batch seqNo and state digest.
	// Users can report any necessary extra field optionally.
	// NOTE. Users should ReportExecuted directly after start node to help track the initial state.
	ReportExecuted(state *types.ServiceState)

	// ReportStateUpdated reports to RBFT core that application service has finished one desired StateUpdate
	// request which was triggered by RBFT core before.
	// Users must ReportStateUpdated after RBFT core invoked StateUpdate request no matter this request was
	// finished successfully or not, otherwise, RBFT core will enter abnormal status infinitely.
	ReportStateUpdated(state *types.ServiceState)
}

// node implements the Node interface and track application service synchronously to help RBFT core
// retrieve service state.
type node[T any, Constraint consensus.TXConstraint[T]] struct {
	// rbft is the actually RBFT service.
	rbft *rbftImpl[T, Constraint]

	// stateLock is used to ensure mutually exclusive access of currentState.
	stateLock sync.RWMutex

	// currentState maintains the current application service state.
	currentState *types.ServiceState

	config Config
	logger Logger
}

// NewNode initializes a Node service.
func NewNode[T any, Constraint consensus.TXConstraint[T]](c Config, external ExternalStack[T, Constraint], requestPool mempool.MemPool[T, Constraint]) (Node[T, Constraint], error) {
	return newNode[T, Constraint](c, external, requestPool)
}

// newNode help to initialize a Node service.
func newNode[T any, Constraint consensus.TXConstraint[T]](c Config, external ExternalStack[T, Constraint], requestPool mempool.MemPool[T, Constraint]) (*node[T, Constraint], error) {
	rbft, err := newRBFT[T, Constraint](c, external, requestPool)
	if err != nil {
		return nil, err
	}

	n := &node[T, Constraint]{
		rbft:   rbft,
		config: c,
		logger: c.Logger,
	}

	rbft.node = n

	return n, nil
}

// Start init Node state.
func (n *node[T, Constraint]) Init() error {
	return n.rbft.init()
}

// Start starts a Node instance.
func (n *node[T, Constraint]) Start() error {
	err := n.rbft.start()
	if err != nil {
		return err
	}

	return nil
}

// Stop stops a Node instance.
func (n *node[T, Constraint]) Stop() [][]byte {
	// stop RBFT core.
	remainTxs := n.rbft.stop()

	n.stateLock.Lock()
	n.currentState = nil
	n.stateLock.Unlock()

	return remainTxs
}

// Propose proposes requests to RBFT core, requests are ensured to be eventually
// submitted to all non-fault nodes unless current node crash down.
func (n *node[T, Constraint]) Propose(requests *consensus.RequestSet) error {
	n.rbft.postRequests(requests)

	return nil
}

// Step advances the state machine using the given message.
func (n *node[T, Constraint]) Step(ctx context.Context, msg *consensus.ConsensusMessage) {
	n.rbft.step(ctx, msg)
}

// ReportExecuted reports to RBFT core that application service has finished height one batch with
// current height batch seqNo and state digest.
// Users can report any necessary extra field optionally.
func (n *node[T, Constraint]) ReportExecuted(state *types.ServiceState) {
	n.stateLock.Lock()
	if n.currentState == nil {
		n.logger.Noticef("Init service state with: %s", state)
		n.currentState = state
		n.stateLock.Unlock()
		return
	}
	if state.MetaState.Height != 0 && state.MetaState.Height <= n.currentState.MetaState.Height {
		n.logger.Warningf("Receive invalid service state %+v, "+
			"current state %+v", state, n.currentState)
		n.stateLock.Unlock()
		return
	}
	n.logger.Debugf("Update service state: %s", state)
	n.currentState = state
	n.stateLock.Unlock()

	// a config transaction executed or checkpoint, send state to checkpoint channel
	n.rbft.reportCheckpoint(state)
}

// ReportStateUpdated reports to RBFT core that application service has finished one desired StateUpdate
// request which was triggered by RBFT core before.
// Users must ReportStateUpdated after RBFT core invoked StateUpdate request no matter this request was
// finished successfully or not, otherwise, RBFT core will enter abnormal status infinitely.
func (n *node[T, Constraint]) ReportStateUpdated(state *types.ServiceState) {
	n.stateLock.Lock()
	if state.MetaState.Height != 0 && state.MetaState.Height <= n.currentState.MetaState.Height {
		n.logger.Infof("Receive a service state with height ID which is not "+
			"larger than current state, received: %+v, current state: %+v", state, n.currentState)
	}
	n.currentState = state
	n.stateLock.Unlock()

	n.rbft.reportStateUpdated(state)
}

// Status returns the current node status of the RBFT state machine.
func (n *node[T, Constraint]) Status() NodeStatus {
	return n.rbft.getStatus()
}

func (n *node[T, Constraint]) GetUncommittedTransactions(maxsize uint64) [][]byte {
	// get hash of transactions that had committed
	var digestList []string
	committedHeight := n.rbft.chainConfig.H
	for digest, batch := range n.rbft.storeMgr.batchStore {
		if batch.SeqNo <= committedHeight {
			digestList = append(digestList, digest)
		}
	}
	// remove committed transactions
	n.rbft.batchMgr.requestPool.RemoveBatches(digestList)

	return n.rbft.batchMgr.requestPool.GetUncommittedTransactions(maxsize)
}

// getCurrentState retrieves the current application state.
func (n *node[T, Constraint]) getCurrentState() *types.ServiceState {
	n.stateLock.RLock()
	defer n.stateLock.RUnlock()
	return n.currentState
}

// GetPendingNonceByAccount returns pendingNonce by given account.
func (n *node[T, Constraint]) GetPendingNonceByAccount(account string) uint64 {
	getNonceReq := &ReqNonceMsg{
		account: account,
		ch:      make(chan uint64),
	}
	localEvent := &MiscEvent{
		EventType: ReqNonceEvent,
		Event:     getNonceReq,
	}
	n.rbft.postMsg(localEvent)

	return <-getNonceReq.ch
}

func (n *node[T, Constraint]) GetPendingTxByHash(hash string) []byte {
	getTxReq := &ReqTxMsg{
		hash: hash,
		ch:   make(chan []byte),
	}
	localEvent := &MiscEvent{
		EventType: ReqTxEvent,
		Event:     getTxReq,
	}
	n.rbft.postMsg(localEvent)

	return <-getTxReq.ch
}
