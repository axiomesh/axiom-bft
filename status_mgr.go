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
	"sync/atomic"

	"github.com/axiomesh/axiom-kit/types"
)

// StatusType defines the RBFT internal status.
type StatusType int

// consensus status type.
const (
	// normal status, which will only be used in rbft
	Normal = iota + 1 // normal consensus state

	// atomic status, which might be used by outer service
	InConfChange      // node is processing a config transaction
	InViewChange      // node is trying to change view
	InRecovery        // node is trying to recover state
	StateTransferring // node is updating state
	Pending           // node cannot process consensus messages
	Stopped           // node has stopped and cannot process consensus messages

	// internal status
	Inconsistent   // inconsistent cluster status, e.g inconsistent checkpoint
	InSyncState    // node is syncing state
	NeedSyncState  // node need to sync state
	SkipInProgress // node try to state update
	byzantine      // byzantine
	InEpochSyncing // in epoch syncing, used to block consensus progress until sync to epoch change height.
	waitCheckpointBatchExecute
	waitCheckpointFinished
)

// NodeStatus reflects the internal consensus status.
type NodeStatus struct {
	ID        uint64
	View      uint64
	EpochInfo *types.EpochInfo
	H         uint64
	Status    StatusType
}

type statusManager struct {
	status       uint32 // consensus status
	atomicStatus uint32
}

func newStatusMgr() *statusManager {
	return &statusManager{}
}

// reset only resets consensus status to 0.
func (st *statusManager) reset() {
	st.status = 0
	atomic.StoreUint32(&st.atomicStatus, 0)
}

// ==================================================
// Atomic Options to Process Atomic Status
// ==================================================
// atomic setBit sets the bit at position in integer n.
func (st *statusManager) atomicSetBit(position uint64) {
	// try CompareAndSwapUint64 until success
	for {
		oldStatus := atomic.LoadUint32(&st.atomicStatus)
		if atomic.CompareAndSwapUint32(&st.atomicStatus, oldStatus, oldStatus|(1<<position)) {
			break
		}
	}
}

// atomic clearBit clears the bit at position in integer n.
func (st *statusManager) atomicClearBit(position uint64) {
	// try CompareAndSwapUint64 until success
	for {
		oldStatus := atomic.LoadUint32(&st.atomicStatus)
		if atomic.CompareAndSwapUint32(&st.atomicStatus, oldStatus, oldStatus&^(1<<position)) {
			break
		}
	}
}

// atomic hasBit checks atomic whether a bit position is set.
func (st *statusManager) atomicHasBit(position uint64) bool {
	val := atomic.LoadUint32(&st.atomicStatus) & (1 << position)
	return val > 0
}

// atomic on sets the atomic status of specified positions.
func (rbft *rbftImpl[T, Constraint]) atomicOn(statusPos ...uint64) {
	for _, pos := range statusPos {
		rbft.status.atomicSetBit(pos)
	}
}

// atomic off resets the atomic status of specified positions.
func (rbft *rbftImpl[T, Constraint]) atomicOff(statusPos ...uint64) {
	for _, pos := range statusPos {
		rbft.status.atomicClearBit(pos)
	}
}

// atomic in returns the atomic status of specified position.
func (rbft *rbftImpl[T, Constraint]) atomicIn(pos uint64) bool {
	s := rbft.status.atomicHasBit(pos)
	return s
}

// atomic inOne checks the result of several atomic status computed with each other using '||'
func (rbft *rbftImpl[T, Constraint]) atomicInOne(poss ...uint64) bool {
	var rs = false
	for _, pos := range poss {
		rs = rs || rbft.atomicIn(pos)
	}
	return rs
}

// ==================================================
// Normal Options to Process Normal Status
// ==================================================
// setBit sets the bit at position in integer n.
func (st *statusManager) setBit(position uint32) {
	st.status |= 1 << position
}

// clearBit clears the bit at position in integer n.
func (st *statusManager) clearBit(position uint32) {
	st.status &= ^(1 << position)
}

// hasBit checks whether a bit position is set.
func (st *statusManager) hasBit(position uint32) bool {
	val := st.status & (1 << position)
	return val > 0
}

// on sets the status of specified positions.
func (rbft *rbftImpl[T, Constraint]) on(statusPos ...uint32) {
	for _, pos := range statusPos {
		rbft.status.setBit(pos)
	}
}

// off resets the status of specified positions.
func (rbft *rbftImpl[T, Constraint]) off(statusPos ...uint32) {
	for _, pos := range statusPos {
		rbft.status.clearBit(pos)
	}
}

// in returns the status of specified position.
func (rbft *rbftImpl[T, Constraint]) in(pos uint32) bool {
	return rbft.status.hasBit(pos)
}

// ==================================================
// Status Tools
// ==================================================
// setNormal sets system to normal.
func (rbft *rbftImpl[T, Constraint]) setNormal() {
	rbft.on(Normal)
	rbft.metrics.statusGaugeInNormal.Set(Normal)
}

// maybeSetNormal checks if system is in normal or not, if in normal, set status to normal.
func (rbft *rbftImpl[T, Constraint]) maybeSetNormal() {
	if !rbft.atomicInOne(InViewChange, Pending, SkipInProgress) {
		rbft.setNormal()
	} else {
		rbft.logger.Debugf("Replica %d not set normal as it's still in abnormal now, current status: {InViewChange: %v, Pending: %v, SkipInProgress: %v}", rbft.chainConfig.SelfID, rbft.atomicIn(InViewChange), rbft.atomicIn(Pending), rbft.atomicIn(SkipInProgress))
	}
}

// setAbNormal sets system to abnormal which means system may be in viewChange, state update...
// we can't do sync state when we are in abnormal.
func (rbft *rbftImpl[T, Constraint]) setAbNormal() {
	rbft.exitSyncState()
	if rbft.isPrimary(rbft.chainConfig.SelfID) {
		rbft.logger.Debug("Old primary stop batch timer before enter abnormal status")
		rbft.stopBatchTimer()
	}
	rbft.off(Normal)
	rbft.metrics.statusGaugeInNormal.Set(0)
}

// isNormal checks setNormal and returns if system is normal or not.
func (rbft *rbftImpl[T, Constraint]) isNormal() bool {
	return rbft.in(Normal)
}

// initStatus init basic status when starts up
func (rbft *rbftImpl[T, Constraint]) initStatus() {
	rbft.status.reset()
	// set consensus status to pending to avoid process consensus messages
	// until RBFT starts recovery
	rbft.atomicOn(Pending)
	rbft.metrics.statusGaugePending.Set(Pending)
}
