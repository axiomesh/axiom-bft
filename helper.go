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
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/ultramesh/flato-common/types"
	"github.com/ultramesh/flato-common/types/protos"
	pb "github.com/ultramesh/flato-rbft/rbftpb"

	"github.com/gogo/protobuf/proto"
)

// =============================================================================
// helper functions for sort
// =============================================================================
type sortableUint64List []uint64

func (a sortableUint64List) Len() int {
	return len(a)
}
func (a sortableUint64List) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a sortableUint64List) Less(i, j int) bool {
	return a[i] < a[j]
}

// =============================================================================
// helper functions for RBFT
// =============================================================================

// primaryID returns the expected primary id with the given view v
func (rbft *rbftImpl) primaryID(v uint64) uint64 {
	// calculate primary id by view
	primaryID := v%uint64(rbft.N) + 1
	return primaryID
}

// isPrimary returns if current node is primary or not
func (rbft *rbftImpl) isPrimary(id uint64) bool {
	// new node cannot become a primary node, directly return false.
	if rbft.in(isNewNode) && id == rbft.peerPool.ID {
		rbft.logger.Debugf("New node cannot become a primary node, no=%d/view=%d/ID=%d",
			rbft.peerPool.ID, rbft.view, rbft.peerPool.ID)
		return false
	}
	return rbft.primaryID(rbft.view) == id
}

// InW returns if the given seqNo is higher than h or not
func (rbft *rbftImpl) inW(n uint64) bool {
	return n > rbft.h
}

// InV returns if the given view equals the current view or not
func (rbft *rbftImpl) inV(v uint64) bool {
	return rbft.view == v
}

// InWV firstly checks if the given view is inV then checks if the given seqNo n is inW
func (rbft *rbftImpl) inWV(v uint64, n uint64) bool {
	return rbft.inV(v) && rbft.inW(n)
}

// sendInW used in maybeSendPrePrepare checks the given seqNo is between low
// watermark and high watermark or not.
func (rbft *rbftImpl) sendInW(n uint64) bool {
	return n > rbft.h && n <= rbft.h+rbft.L
}

// cleanAllBatchAndCert cleans all outstandingReqBatches and committedCert
func (rbft *rbftImpl) cleanOutstandingAndCert() {
	rbft.storeMgr.outstandingReqBatches = make(map[string]*pb.RequestBatch)
	rbft.storeMgr.committedCert = make(map[msgID]string)

	rbft.metrics.outstandingBatchesGauge.Set(float64(0))
}

// When N=3F+1, this should be 2F+1 (N-F)
// More generally, we need every two common case quorum of size X to intersect in at least F+1
// hence 2X>=N+F+1
func (rbft *rbftImpl) commonCaseQuorum() int {
	return int(math.Ceil(float64(rbft.N+rbft.f+1) / float64(2)))
}

// oneCorrectQuorum returns the number of replicas in which correct numbers must be bigger than incorrect number
func (rbft *rbftImpl) allCorrectReplicasQuorum() int {
	return rbft.N - rbft.f
}

// oneCorrectQuorum returns the number of replicas in which there must exist at least one correct replica
func (rbft *rbftImpl) oneCorrectQuorum() int {
	return rbft.f + 1
}

// =============================================================================
// pre-prepare/prepare/commit check helper
// =============================================================================

// prePrepared returns if there existed a pre-prepare message in certStore with the given digest,view,seqNo
func (rbft *rbftImpl) prePrepared(digest string, v uint64, n uint64) bool {
	// TODO(DH): we need to ensure that we actually have the request batch.
	cert := rbft.storeMgr.certStore[msgID{v, n, digest}]

	if cert != nil {
		p := cert.prePrepare
		if p != nil && p.View == v && p.SequenceNumber == n && p.BatchDigest == digest {
			return true
		}
	}

	rbft.logger.Debugf("Replica %d does not have view=%d/seqNo=%d prePrepared", rbft.peerPool.ID, v, n)

	return false
}

// prepared firstly checks if the cert with the given msgID has been prePrepared,
// then checks if this node has collected enough prepare messages for the cert with given msgID
func (rbft *rbftImpl) prepared(digest string, v uint64, n uint64) bool {

	if !rbft.prePrepared(digest, v, n) {
		return false
	}

	cert := rbft.storeMgr.certStore[msgID{v, n, digest}]

	prepCount := len(cert.prepare)

	rbft.logger.Debugf("Replica %d prepare count for view=%d/seqNo=%d is %d",
		rbft.peerPool.ID, v, n, prepCount)

	return prepCount >= rbft.commonCaseQuorum()-1
}

// committed firstly checks if the cert with the given msgID has been prepared,
// then checks if this node has collected enough commit messages for the cert with given msgID
func (rbft *rbftImpl) committed(digest string, v uint64, n uint64) bool {

	if !rbft.prepared(digest, v, n) {
		return false
	}

	cert := rbft.storeMgr.certStore[msgID{v, n, digest}]

	cmtCount := len(cert.commit)

	rbft.logger.Debugf("Replica %d commit count for view=%d/seqNo=%d is %d",
		rbft.peerPool.ID, v, n, cmtCount)

	return cmtCount >= rbft.commonCaseQuorum()
}

// =============================================================================
// helper functions for transfer message
// =============================================================================

// broadcastReqSet helps broadcast requestSet to others.
func (rbft *rbftImpl) broadcastReqSet(set *pb.RequestSet) {
	if rbft.requestSethMemLimit {
		rbft.limitRequestSet(set)
	} else {
		rbft.normalRequestSet(set)
	}
}

func (rbft *rbftImpl) normalRequestSet(set *pb.RequestSet) {
	payload, err := proto.Marshal(set)
	if err != nil {
		rbft.logger.Errorf("ConsensusMessage_TRANSACTION_SET Marshal Error: %s", err)
		return
	}
	consensusMsg := &pb.ConsensusMessage{
		Type:    pb.Type_REQUEST_SET,
		From:    rbft.peerPool.ID,
		Epoch:   rbft.epoch,
		Payload: payload,
	}
	rbft.peerPool.broadcast(consensusMsg)
}

func (rbft *rbftImpl) limitRequestSet(set *pb.RequestSet) {
	rbft.logger.Debugf("Replica %d broadcast request set with memory limit", rbft.peerPool.ID)
	var newTxList []*protos.Transaction
	var requestSet *pb.RequestSet
	txList := set.Requests
	local := set.Local
	for len(txList) != 0 {
		if ok, rate := rbft.checkRequestSetMemCap(txList); ok {
			rbft.logger.Debugf("rate: %f, len txList: %d", rate, len(txList))
			newTxList = rbft.splitTxFromRequestSet(rate, txList)
		} else {
			newTxList = txList
		}
		requestSet = &pb.RequestSet{
			Requests: newTxList,
			Local:    local,
		}
		txList = txList[len(newTxList):]
		rbft.normalRequestSet(requestSet)
		rbft.logger.Debugf("Replica %d broadcast a request batch with %d transactions, memCap %d, %d transactions remain",
			rbft.peerPool.ID, len(newTxList), proto.Size(requestSet), len(txList))
	}
}

// checkRequestSetMemCap checks if mem size of given request set has exceeded the "requestSetMaxMem",
// if so return the exceed rate.
func (rbft *rbftImpl) checkRequestSetMemCap(txList []*protos.Transaction) (bool, float64) {
	set := &pb.RequestSet{
		Requests: txList,
		Local:    true,
	}
	memCap := proto.Size(set)
	if memCap > rbft.requestSetMaxMem {
		rate, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(memCap)/float64(rbft.requestSetMaxMem)), 64)
		return true, rate
	}
	return false, 0
}

// splitTxFromBatch split the element from txList until the batch memory size less than
// "batchMaxMem" or there is only one remained transaction.
func (rbft *rbftImpl) splitTxFromRequestSet(rate float64, txList []*protos.Transaction) []*protos.Transaction {
	var newTxList []*protos.Transaction

	if len(txList) == 1 {
		return txList
	}

	surplus := int(float64(len(txList)) / rate)

	if surplus == 0 || surplus == 1 {
		return txList[0:1]
	}
	newTxList = txList[0:surplus]
	if ok, rate := rbft.checkRequestSetMemCap(newTxList); ok {
		newTxList = rbft.splitTxFromRequestSet(rate, newTxList)
	}

	return newTxList
}

// =============================================================================
// helper functions for timer
// =============================================================================

// startTimerIfOutstandingRequests soft starts a new view timer if there exists some outstanding request batches,
// else reset the null request timer
func (rbft *rbftImpl) startTimerIfOutstandingRequests() {
	if rbft.in(SkipInProgress) || rbft.exec.currentExec != nil {
		// Do not start the view change timer if we are executing or state transferring, these take arbitrarily long amounts of time
		return
	}

	if len(rbft.storeMgr.outstandingReqBatches) > 0 {
		getOutstandingDigests := func() []string {
			var digests []string
			for digest := range rbft.storeMgr.outstandingReqBatches {
				digests = append(digests, digest)
			}
			return digests
		}()
		rbft.softStartNewViewTimer(rbft.timerMgr.getTimeoutValue(requestTimer), fmt.Sprintf("outstanding request "+
			"batches num=%v, batches: %v", len(getOutstandingDigests), getOutstandingDigests), false)
	} else if rbft.timerMgr.getTimeoutValue(nullRequestTimer) > 0 {
		rbft.nullReqTimerReset()
	}
}

// nullReqTimerReset reset the null request timer with a certain timeout, for different replica, null request timeout is
// different:
// 1. for primary, null request timeout is the timeout written in the config
// 2. for non-primary, null request timeout =3*(timeout written in the config)+request timeout
func (rbft *rbftImpl) nullReqTimerReset() {
	timeout := rbft.timerMgr.getTimeoutValue(nullRequestTimer)
	if !rbft.isPrimary(rbft.peerPool.ID) {
		// we're waiting for the primary to deliver a null request - give it a bit more time
		timeout = 3*timeout + rbft.timerMgr.getTimeoutValue(requestTimer)
	}

	event := &LocalEvent{
		Service:   CoreRbftService,
		EventType: CoreNullRequestTimerEvent,
	}

	rbft.timerMgr.startTimerWithNewTT(nullRequestTimer, timeout, event)
}

// stopFirstRequestTimer stops the first request timer event if current node is not primary
func (rbft *rbftImpl) stopFirstRequestTimer() {
	if !rbft.isPrimary(rbft.peerPool.ID) {
		rbft.timerMgr.stopTimer(firstRequestTimer)
	}
}

// =============================================================================
// helper functions for check the validity of consensus messages
// =============================================================================
// isPrePrepareLegal firstly checks if current status can receive pre-prepare or not, then checks pre-prepare message
// itself is legal or not
func (rbft *rbftImpl) isPrePrepareLegal(preprep *pb.PrePrepare) bool {

	if rbft.atomicIn(InRecovery) {
		rbft.logger.Debugf("Replica %d try to receive prePrepare, but it's in recovery", rbft.peerPool.ID)
		return false
	}

	if rbft.atomicIn(InViewChange) {
		rbft.logger.Debugf("Replica %d try to receive prePrepare, but it's in viewChange", rbft.peerPool.ID)
		return false
	}

	if rbft.atomicIn(InConfChange) {
		rbft.logger.Debugf("Replica %d try to receive prePrepare, but it's in confChange", rbft.peerPool.ID)
		return false
	}

	// replica rejects prePrepare sent from non-primary.
	if !rbft.isPrimary(preprep.ReplicaId) {
		primaryID := rbft.primaryID(rbft.view)
		rbft.logger.Warningf("Replica %d received prePrepare from non-primary: got %d, should be %d",
			rbft.peerPool.ID, preprep.ReplicaId, primaryID)
		return false
	}

	// primary reject prePrepare sent from itself.
	if rbft.isPrimary(rbft.peerPool.ID) {
		rbft.logger.Warningf("Primary %d reject prePrepare sent from itself", rbft.peerPool.ID)
		return false
	}

	if !rbft.inWV(preprep.View, preprep.SequenceNumber) {
		if preprep.SequenceNumber != rbft.h && !rbft.in(SkipInProgress) {
			rbft.logger.Warningf("Replica %d received prePrepare with a different view or sequence "+
				"number outside watermarks: prePrep.View %d, expected.View %d, seqNo %d, low water mark %d",
				rbft.peerPool.ID, preprep.View, rbft.view, preprep.SequenceNumber, rbft.h)
		} else {
			// This is perfectly normal
			rbft.logger.Debugf("Replica %d received prePrepare with a different view or sequence "+
				"number outside watermarks: preprep.View %d, expected.View %d, seqNo %d, low water mark %d",
				rbft.peerPool.ID, preprep.View, rbft.view, preprep.SequenceNumber, rbft.h)
		}
		return false
	}

	if preprep.SequenceNumber <= rbft.exec.lastExec {
		rbft.logger.Debugf("Replica %d received a prePrepare with seqNo %d lower than lastExec %d, ignore it...", rbft.peerPool.ID, preprep.SequenceNumber, rbft.exec.lastExec)
		return false
	}

	return true
}

// isPrepareLegal firstly checks if current status can receive prepare or not, then checks prepare message itself is
// legal or not
func (rbft *rbftImpl) isPrepareLegal(prep *pb.Prepare) bool {

	// if we are not in recovery, but receive prepare from primary, which means primary behavior as a byzantine,
	// we don't send viewchange here, because in this case, replicas will eventually find primary abnormal in other cases.
	if rbft.isPrimary(prep.ReplicaId) {
		rbft.logger.Debugf("Replica %d received prepare from primary, ignore it", rbft.peerPool.ID)
		return false
	}

	if !rbft.inWV(prep.View, prep.SequenceNumber) {
		if prep.SequenceNumber != rbft.h && !rbft.in(SkipInProgress) {
			rbft.logger.Warningf("Replica %d ignore prepare from replica %d for view=%d/seqNo=%d: not inWv, in view: %d, h: %d",
				rbft.peerPool.ID, prep.ReplicaId, prep.View, prep.SequenceNumber, rbft.view, rbft.h)
		} else {
			// This is perfectly normal
			rbft.logger.Debugf("Replica %d ignore prepare from replica %d for view=%d/seqNo=%d: not inWv, in view: %d, h: %d",
				rbft.peerPool.ID, prep.ReplicaId, prep.View, prep.SequenceNumber, rbft.view, rbft.h)
		}

		return false
	}
	return true
}

// isCommitLegal firstly checks if current status can receive commit or not, then checks commit message itself is legal
// or not
func (rbft *rbftImpl) isCommitLegal(commit *pb.Commit) bool {

	if !rbft.inWV(commit.View, commit.SequenceNumber) {
		if commit.SequenceNumber != rbft.h && !rbft.in(SkipInProgress) {
			rbft.logger.Warningf("Replica %d ignore commit from replica %d for view=%d/seqNo=%d: not inWv, in view: %d, h: %d",
				rbft.peerPool.ID, commit.ReplicaId, commit.View, commit.SequenceNumber, rbft.view, rbft.h)
		} else {
			// This is perfectly normal
			rbft.logger.Debugf("Replica %d ignore commit from replica %d for view=%d/seqNo=%d: not inWv, in view: %d, h: %d",
				rbft.peerPool.ID, commit.ReplicaId, commit.View, commit.SequenceNumber, rbft.view, rbft.h)
		}
		return false
	}
	return true
}

// compareCheckpointWithWeakSet first checks the legality of this checkpoint, which seqNo
// must between [h, H] and we haven't received a same checkpoint message, then find the
// weak set with more than f + 1 members who have sent a checkpoint with the same seqNo
// and ID, if there exists more than one weak sets, we'll never find a stable cert for this
// seqNo, else checks if self's generated checkpoint has the same ID with the given one,
// if not, directly start state update to recover to a correct state.
func (rbft *rbftImpl) compareCheckpointWithWeakSet(chkpt *pb.Checkpoint) (bool, int) {
	// if checkpoint height is lower than current low watermark, ignore it as we have reached a higher h,
	// else, continue to find f+1 checkpoint messages with the same seqNo and ID
	if !rbft.inW(chkpt.SequenceNumber) {
		if chkpt.SequenceNumber != rbft.h && !rbft.in(SkipInProgress) {
			// It is perfectly normal that we receive checkpoints for the watermark we just raised, as we raise it after 2f+1, leaving f replies left
			rbft.logger.Warningf("Checkpoint sequence number outside watermarks: seqNo %d, low water mark %d", chkpt.SequenceNumber, rbft.h)
		} else {
			rbft.logger.Debugf("Checkpoint sequence number outside watermarks: seqNo %d, low water mark %d", chkpt.SequenceNumber, rbft.h)
		}
		return false, 0
	}

	if rbft.storeMgr.checkpointStore[*chkpt] {
		rbft.logger.Warningf("Replica %d ignore duplicate checkpoint from replica %d, seqNo=%d", rbft.peerPool.ID, chkpt.ReplicaId, chkpt.SequenceNumber)
		return false, 0
	}
	rbft.storeMgr.checkpointStore[*chkpt] = true

	// track how many different checkpoint values we have for the seqNo.
	diffValues := make(map[string][]uint64)
	// track how many "correct"(more than f + 1) checkpoint values we have for the seqNo.
	var correctValues []string

	// track totally matching checkpoints.
	matching := 0
	for cp := range rbft.storeMgr.checkpointStore {
		if cp.SequenceNumber != chkpt.SequenceNumber {
			continue
		}

		if cp.Digest == chkpt.Digest {
			matching++
		}

		if _, ok := diffValues[cp.Digest]; !ok {
			diffValues[cp.Digest] = []uint64{cp.ReplicaId}
		} else {
			diffValues[cp.Digest] = append(diffValues[cp.Digest], cp.ReplicaId)
		}

		// if current network contains more than f + 1 checkpoints with the same seqNo
		// but different ID, we'll never be able to get a stable cert for this seqNo.
		if len(diffValues) > rbft.f+1 {
			rbft.logger.Criticalf("Replica %d cannot find stable checkpoint with seqNo %d"+
				"(%d different values observed already).", rbft.peerPool.ID, chkpt.SequenceNumber, len(diffValues))
			rbft.atomicOn(Pending)
			rbft.metrics.statusGaugePending.Set(Pending)
			rbft.setAbNormal()
			rbft.stopNamespace()
			return false, 0
		}

		// record all correct checkpoint(weak cert) values.
		if len(diffValues[cp.Digest]) == rbft.f+1 {
			correctValues = append(correctValues, cp.Digest)
		}
	}

	if len(correctValues) == 0 {
		rbft.logger.Debugf("Replica %d hasn't got a weak cert for checkpoint %d", rbft.peerPool.ID, chkpt.SequenceNumber)
		return true, matching
	}

	// if we encounter more than one correct weak set, we will never recover to a stable
	// consensus state.
	if len(correctValues) > 1 {
		rbft.logger.Criticalf("Replica %d finds several weak certs for checkpoint %d, values: %v", rbft.peerPool.ID, chkpt.SequenceNumber, correctValues)
		rbft.atomicOn(Pending)
		rbft.metrics.statusGaugePending.Set(Pending)
		rbft.setAbNormal()
		rbft.stopNamespace()
		return false, 0
	}

	// if we can only find one weak cert with the same seqNo and ID, our generated checkpoint(if
	// existed) must have the same ID with that one.
	correctID := correctValues[0]
	selfID, ok := rbft.storeMgr.chkpts[chkpt.SequenceNumber]
	// if self's checkpoint with the same seqNo has a distinguished ID with a weak certs'
	// checkpoint ID, we should trigger state update right now to recover self block state.
	if ok && selfID != correctID {
		rbft.logger.Criticalf("Replica %d generated a checkpoint of %s, but a weak set of the network agrees on %s.",
			rbft.peerPool.ID, selfID, correctID)

		target := &pb.MetaState{
			Applied: chkpt.SequenceNumber,
			Digest:  correctID,
		}
		rbft.updateHighStateTarget(target)
		rbft.tryStateTransfer()
		return false, 0
	}

	return true, matching
}

// compareWholeStates compares whole networks' current status during recovery or sync state
// Those status including :
// 1. N: current consensus nodes number
// 2. epoch: current epoch of bft network
// 3. view: current view of bft network
// 4. applied(only compared in sync state): current latest blockChain height
// 5. digest(only compared in sync state): current latest blockChain hash
func (rbft *rbftImpl) compareWholeStates(states wholeStates) consensusEvent {
	// track all replica hash with same state used to update routing table if needed
	sameRespCount := make(map[nodeState][]string)

	// check if we can find quorum nodeState who have the same n and view, routerMap, if we can find, which means
	// quorum nodes agree to a N and view, save to quorumRsp, set canFind to true and update N, view if needed
	var quorumResp nodeState
	canFind := false

	// find the quorum nodeState
	for key, state := range states {
		sameRespCount[state] = append(sameRespCount[state], key.ReplicaHash)
		// If quorum agree with a same N,view,epoch, check if we need to update routing table first.
		// As for quorum will be changed according to validator set, and we cannot be sure that router info of
		// the node is correct, we should calculate the commonCaseQuorum with the N of state.
		if len(sameRespCount[state]) >= rbft.commonCaseQuorum() {
			rbft.logger.Debugf("Replica %d find quorum states, try to process", rbft.peerPool.ID)
			quorumResp = state
			canFind = true
			break
		}
	}

	// we can find the quorum nodeState with the same N and view, judge if the response.view equals to the
	// current view, if so, just update N and view, else update N, view and then re-constructs certStore
	if canFind {
		// update view if we need it and we needn't sync epoch
		if rbft.view != quorumResp.view && !rbft.recoveryMgr.needSyncEpoch {
			rbft.setView(quorumResp.view)
			rbft.logger.Infof("Replica %d persist view=%d after found quorum same response.", rbft.peerPool.ID, rbft.view)
			rbft.persistView(rbft.view)
		}

		if rbft.in(InSyncState) {
			// get self-state to compare
			state := rbft.node.getCurrentState()

			// we could stop sync-state timer here as we has already found quorum sync-state-response
			rbft.timerMgr.stopTimer(syncStateRspTimer)
			rbft.off(InSyncState)

			// case 1) wrong epoch [sync]:
			// self epoch is lower than the others and we need to find correct epoch-info at first
			// trigger state-update
			if quorumResp.epoch > rbft.epoch {
				rbft.logger.Warningf("Replica %d finds quorum same epoch %d, which is lager than self epoch %d, "+
					"need to state update", rbft.peerPool.ID, quorumResp.epoch, rbft.epoch)

				target := &pb.MetaState{
					Applied: quorumResp.applied,
					Digest:  quorumResp.digest,
				}
				rbft.updateHighStateTarget(target)
				rbft.tryStateTransfer()
				return nil
			}

			// case 2) wrong height [sync]:
			// self height of blocks is lower than others
			// trigger recovery
			if state.MetaState.Applied != quorumResp.applied {
				rbft.logger.Noticef("Replica %d finds quorum same block state which is different from self,"+
					"self height: %d, quorum height: %d",
					rbft.peerPool.ID, state.MetaState.Applied, quorumResp.applied)

				// node in lower height cannot become a primary node
				if rbft.isPrimary(rbft.peerPool.ID) {
					rbft.logger.Warningf("Primary %d finds itself not sync with quorum replicas, sending viewChange", rbft.peerPool.ID)
					return rbft.sendViewChange()
				}
				rbft.logger.Infof("Replica %d finds itself not sync with quorum replicas, try to recovery", rbft.peerPool.ID)
				return rbft.initRecovery()
			}

			// case 3) wrong block hash [error]:
			// we have correct epoch and block-height, but the hash of latest block is wrong
			// trigger state-update
			if state.MetaState.Applied == quorumResp.applied && state.MetaState.Digest != quorumResp.digest {
				rbft.logger.Errorf("Replica %d finds quorum same block state whose hash is different from self,"+
					"in height: %d, selfHash: %s, quorumDigest: %s, need to state update",
					rbft.peerPool.ID, quorumResp.applied, state.MetaState.Digest, quorumResp.digest)

				target := &pb.MetaState{
					Applied: quorumResp.applied,
					Digest:  quorumResp.digest,
				}
				rbft.updateHighStateTarget(target)
				rbft.tryStateTransfer()
				return nil
			}

			rbft.logger.Infof("======== Replica %d finished sync state for height: %d, current epoch: %d, current view %d",
				rbft.peerPool.ID, state.MetaState.Applied, rbft.epoch, rbft.view)
			rbft.external.SendFilterEvent(pb.InformType_FilterStableCheckpoint, quorumResp.applied, quorumResp.digest)
			return nil
		}

		if rbft.atomicIn(InRecovery) {
			// if current node finds itself become primary, but quorum other replicas
			// are in normal status, directly send viewChange as we don't want to
			// resend prePrepares after sync view.
			if rbft.isPrimary(rbft.peerPool.ID) {
				rbft.logger.Warningf("Replica %d become primary after sync view, sending viewChange", rbft.peerPool.ID)
				rbft.timerMgr.stopTimer(recoveryRestartTimer)
				rbft.atomicOff(InRecovery)
				rbft.metrics.statusGaugeInRecovery.Set(0)
				rbft.sendViewChange()
				return nil
			}

			return rbft.resetStateForRecovery()
		}
	}

	return nil
}

// calcQSet selects Pre-prepares which satisfy the following conditions
// 1. Pre-prepares in previous qlist
// 2. Pre-prepares from certStore which is preprepared and its view <= its idx.v or not in qlist
func (rbft *rbftImpl) calcQSet() map[qidx]*pb.Vc_PQ {

	qset := make(map[qidx]*pb.Vc_PQ)

	for n, q := range rbft.vcMgr.qlist {
		qset[n] = q
	}

	for idx := range rbft.storeMgr.certStore {

		if !rbft.prePrepared(idx.d, idx.v, idx.n) {
			continue
		}

		qi := qidx{idx.d, idx.n}
		if q, ok := qset[qi]; ok && q.View > idx.v {
			continue
		}

		qset[qi] = &pb.Vc_PQ{
			SequenceNumber: idx.n,
			BatchDigest:    idx.d,
			View:           idx.v,
		}
	}

	return qset
}

// calcPSet selects prepares which satisfy the following conditions:
// 1. prepares in previous qlist
// 2. prepares from certStore which is prepared and (its view <= its idx.v or not in plist)
func (rbft *rbftImpl) calcPSet() map[uint64]*pb.Vc_PQ {

	pset := make(map[uint64]*pb.Vc_PQ)

	for n, p := range rbft.vcMgr.plist {
		pset[n] = p
	}

	for idx := range rbft.storeMgr.certStore {

		if !rbft.prepared(idx.d, idx.v, idx.n) {
			continue
		}

		if p, ok := pset[idx.n]; ok && p.View > idx.v {
			continue
		}

		pset[idx.n] = &pb.Vc_PQ{
			SequenceNumber: idx.n,
			BatchDigest:    idx.d,
			View:           idx.v,
		}
	}

	return pset
}

// getVcBasis helps re-calculate the plist and qlist then construct a vcBasis
// at teh same time, useless cert with lower .
func (rbft *rbftImpl) getVcBasis() *pb.VcBasis {
	basis := &pb.VcBasis{
		View:      rbft.view,
		H:         rbft.h,
		ReplicaId: rbft.peerPool.ID,
	}

	// clear qList and pList from DB as we will construct new QPList next.
	rbft.persistDelQPList()

	rbft.vcMgr.plist = rbft.calcPSet()
	rbft.vcMgr.qlist = rbft.calcQSet()

	// Note. before vc/recovery, we need to persist QPList to ensure we can restore committed entries after
	// above abnormal situations as we will delete all PQCSet when we enter abnormal, after finish vc/recovery
	// we will re-broadcast and persist PQCSet which is enough to ensure continuity of committed entries in
	// next vc/recovery. However, QPList cannot be deleted immediately after finish vc/recovery as we may loss
	// some committed entries after crash down in normal status.
	// So:
	// 1. during normal status, we have: QPSet with pre-prepare certs and prepare certs and QPList generated in
	// previous abnormal status which is used to catch some useful committed entries after system crash down.
	// 2. during abnormal status, we have no QPSet but we have QPList generated in current abnormal status.
	rbft.persistPList(rbft.vcMgr.plist)
	rbft.persistQList(rbft.vcMgr.qlist)

	for idx := range rbft.storeMgr.certStore {
		if idx.v < rbft.view {
			rbft.logger.Debugf("Replica %d clear cert with view=%d/seqNo=%d/digest=%s when construct VcBasis",
				rbft.peerPool.ID, idx.v, idx.n, idx.d)
			delete(rbft.storeMgr.certStore, idx)
			delete(rbft.storeMgr.seqMap, idx.n)
			rbft.persistDelQPCSet(idx.v, idx.n, idx.d)
		}
	}

	basis.Cset, basis.Pset, basis.Qset = rbft.gatherPQC()

	return basis
}

// gatherPQC just gather all checkpoints, p entries and q entries.
func (rbft *rbftImpl) gatherPQC() (cset []*pb.Vc_C, pset []*pb.Vc_PQ, qset []*pb.Vc_PQ) {
	// Gather all the checkpoints
	rbft.logger.Debugf("Replica %d gather CSet:", rbft.peerPool.ID)
	for n, id := range rbft.storeMgr.chkpts {
		cset = append(cset, &pb.Vc_C{
			SequenceNumber: n,
			Digest:         id,
		})
		rbft.logger.Debugf("seqNo: %d, ID: %s", n, id)
	}
	// Gather all the p entries
	rbft.logger.Debugf("Replica %d gather PSet:", rbft.peerPool.ID)
	for _, p := range rbft.vcMgr.plist {
		if p.SequenceNumber < rbft.h {
			rbft.logger.Errorf("Replica %d should not have anything in our pset less than h, found %+v", rbft.peerPool.ID, p)
			continue
		}
		pset = append(pset, p)
		rbft.logger.Debugf("seqNo: %d, view: %d, digest: %s", p.SequenceNumber, p.View, p.BatchDigest)
	}

	// Gather all the q entries
	rbft.logger.Debugf("Replica %d gather QSet:", rbft.peerPool.ID)
	for _, q := range rbft.vcMgr.qlist {
		if q.SequenceNumber < rbft.h {
			rbft.logger.Errorf("Replica %d should not have anything in our qset less than h, found %+v", rbft.peerPool.ID, q)
			continue
		}
		qset = append(qset, q)
		rbft.logger.Debugf("seqNo: %d, view: %d, digest: %s", q.SequenceNumber, q.View, q.BatchDigest)
	}

	return
}

// putBackRequestBatches reset all txs into 'non-batched' state in requestPool to prepare re-arrange by order.
func (rbft *rbftImpl) putBackRequestBatches(xset xset) {

	// remove all the batches that smaller than initial checkpoint.
	// those batches are the dependency of duplicator,
	// but we can remove since we already have checkpoint after viewChange.
	var deleteList []string
	for digest, batch := range rbft.storeMgr.batchStore {
		if batch.SeqNo <= rbft.h {
			rbft.logger.Debugf("Replica %d clear batch %s with seqNo %d <= initial checkpoint %d", rbft.peerPool.ID, digest, batch.SeqNo, rbft.h)
			delete(rbft.storeMgr.batchStore, digest)
			rbft.persistDelBatch(digest)
			deleteList = append(deleteList, digest)
		}
	}
	rbft.metrics.batchesGauge.Set(float64(len(rbft.storeMgr.batchStore)))
	rbft.batchMgr.requestPool.RemoveBatches(deleteList)

	if !rbft.batchMgr.requestPool.IsPoolFull() {
		rbft.setNotFull()
	}

	// directly restore all batchedTxs back into non-batched txs and re-arrange them by order when processNewView.
	rbft.batchMgr.requestPool.RestorePool()

	// clear cacheBatch as they are useless and all related batches have been restored in requestPool.
	rbft.batchMgr.cacheBatch = nil

	rbft.metrics.cacheBatchNumber.Set(float64(0))

	hashListMap := make(map[string]bool)
	for _, hash := range xset {
		hashListMap[hash] = true
	}

	// don't remove those batches which are not contained in xSet from batchStore as they may be useful
	// in next viewChange round.
	for digest := range rbft.storeMgr.batchStore {
		if hashListMap[digest] == false {
			rbft.logger.Debugf("Replica %d finds temporarily useless batch %s which is not contained in xSet", rbft.peerPool.ID, digest)
		}
	}
}

// checkIfNeedStateUpdate checks if a replica needs to do state update
func (rbft *rbftImpl) checkIfNeedStateUpdate(initialCp pb.Vc_C) (bool, error) {

	lastExec := rbft.exec.lastExec
	seq := initialCp.SequenceNumber
	dig := initialCp.Digest

	if rbft.exec.currentExec != nil {
		lastExec = *rbft.exec.currentExec
	}

	if rbft.h < seq {
		// if we have reached this checkpoint height locally but haven't move h to
		// this height(may be caused by missing checkpoint msg from other nodes),
		// directly move watermarks to this checkpoint height as we have reached
		// this stable checkpoint normally.
		if rbft.storeMgr.chkpts[seq] == dig {
			rbft.moveWatermarks(seq)
			rbft.external.SendFilterEvent(pb.InformType_FilterStableCheckpoint, seq, dig)
		}

		if rbft.epochMgr.configBatchToCheck != nil {
			if seq == rbft.epochMgr.configBatchToCheck.Applied {
				rbft.logger.Noticef("Replica %d sent a config checkpoint, waiting for commit-db finished...", rbft.peerPool.ID)
				ev := <-rbft.confChan
				if ev.Height != seq {
					err := errors.New("wrong commit-db height")
					rbft.logger.Errorf("Wrong commit-db height: %d", ev.Height)
					rbft.stopNamespace()
					return false, err
				}
				rbft.epochMgr.configBatchToCheck = nil
			}
		}
	}

	// If replica's lastExec < initial checkpoint, replica is out of date
	if lastExec < initialCp.SequenceNumber {
		rbft.logger.Warningf("Replica %d missing base checkpoint %d (%s), our most recent execution %d", rbft.peerPool.ID, initialCp.SequenceNumber, initialCp.Digest, lastExec)

		target := &pb.MetaState{
			Applied: initialCp.SequenceNumber,
			Digest:  initialCp.Digest,
		}

		rbft.updateHighStateTarget(target)
		rbft.tryStateTransfer()
		return true, nil
	}

	return false, nil
}

func (rbft *rbftImpl) getNodeInfo() *pb.NodeInfo {
	return &pb.NodeInfo{
		ReplicaId:   rbft.peerPool.ID,
		ReplicaHash: rbft.peerPool.hash,
	}
}

func (rbft *rbftImpl) inRouters(hash string) bool {
	_, ok := rbft.peerPool.routerMap.HashMap[hash]
	if ok {
		return true
	}
	rbft.logger.Warningf("Replica %d cannot find %s in routers,", rbft.peerPool.ID, hash)
	return false
}

func (rbft *rbftImpl) equalMetaState(s1 *pb.MetaState, s2 *pb.MetaState) bool {
	rbft.logger.Debugf("Replica %d check if meta states are equal: 1)%+v, 2)%+v", rbft.peerPool.ID, s1, s2)

	// nil pointer cannot be checked
	if s1 == nil || s2 == nil {
		return false
	}

	// check the applied number
	if s1.Applied != s2.Applied {
		return false
	}
	// check the digest of the state
	if s1.Digest != s2.Digest {
		return false
	}
	return true
}

func (rbft *rbftImpl) stopNamespace() {
	defer func() {
		// delFlag channel might be closed by other modules at the same time
		// consensus requests to stop namespace
		if err := recover(); err != nil {
			rbft.logger.Warningf("Replica %d stops namespace error: %s", rbft.peerPool.ID, err)
		}
	}()

	rbft.logger.Criticalf("Replica %d requests to stop namespace", rbft.peerPool.ID)
	rbft.delFlag <- true
}

func requestHash(tx *protos.Transaction) string {
	return types.GetHash(tx).Hex()
}

// calculateMD5Hash calculate hash by MD5
func calculateMD5Hash(list []string, timestamp int64) string {
	h := md5.New()
	for _, hash := range list {
		_, _ = h.Write([]byte(hash))
	}
	if timestamp > 0 {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(timestamp))
		_, _ = h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}
