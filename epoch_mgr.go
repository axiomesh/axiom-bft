package rbft

import (
	"sync"

	pb "github.com/hyperchain/go-hpc-rbft/rbftpb"
	"github.com/hyperchain/go-hpc-rbft/types"

	"github.com/gogo/protobuf/proto"
)

// epochManager manages the epoch structure for RBFT.
type epochManager struct {

	// storage for node to check if it has been out of epoch
	checkOutOfEpoch map[uint64]uint64

	// storage for the state of config batch which is waiting for stable-verification
	// it might be assigned at the initiation of epoch-manager
	// it will be assigned after config-batch's execution to check a stable-state
	configBatchToCheck *types.MetaState

	// track the sequence number of the config transaction to execute
	// to notice Node transfer state related to config transactions into core
	configBatchToExecute uint64

	// mutex to set value of configBatchToExecute
	configBatchToExecuteLock sync.RWMutex

	// logger
	logger Logger
}

func newEpochManager(c Config) *epochManager {
	em := &epochManager{
		checkOutOfEpoch:      make(map[uint64]uint64),
		configBatchToCheck:   nil,
		configBatchToExecute: uint64(0),

		logger: c.Logger,
	}

	if c.LatestConfig == nil {
		return em
	}

	// if the height of block is equal to the latest config batch,
	// we are not sure if such a config batch has been checked for stable yet or not,
	// so that, update the config-batch-to-check to trigger a stable point check
	if c.LatestConfig.Height == c.Applied {
		em.logger.Noticef("Latest config batch height %d equal to last exec, which may be non-stable",
			c.LatestConfig.Height)
		em.configBatchToCheck = c.LatestConfig
	}

	return em
}

// dispatchRecoveryMsg dispatches recovery service messages using service type
func (rbft *rbftImpl) dispatchEpochMsg(e consensusEvent) consensusEvent {
	switch et := e.(type) {
	case *pb.FetchCheckpoint:
		return rbft.recvFetchCheckpoint(et)
	}
	return nil
}

func (rbft *rbftImpl) fetchCheckpoint() consensusEvent {
	if rbft.epochMgr.configBatchToCheck == nil {
		rbft.logger.Debugf("Replica %d doesn't need to check any batches", rbft.peerPool.ID)
		return nil
	}

	fetch := &pb.FetchCheckpoint{
		ReplicaHost:    rbft.peerPool.hostname,
		SequenceNumber: rbft.epochMgr.configBatchToCheck.Height,
	}
	rbft.startFetchCheckpointTimer()

	payload, err := proto.Marshal(fetch)
	if err != nil {
		rbft.logger.Errorf("ConsensusMessage_PREPARE Marshal Error: %s", err)
		return nil
	}
	consensusMsg := &pb.ConsensusMessage{
		Type:    pb.Type_FETCH_CHECKPOINT,
		From:    rbft.peerPool.ID,
		Epoch:   rbft.epoch,
		Payload: payload,
	}

	rbft.logger.Debugf("Replica %d is fetching checkpoint %d", rbft.peerPool.ID, fetch.SequenceNumber)
	rbft.peerPool.broadcast(consensusMsg)
	return nil
}

func (rbft *rbftImpl) startFetchCheckpointTimer() {
	event := &LocalEvent{
		Service:   EpochMgrService,
		EventType: FetchCheckpointEvent,
	}
	// use fetchCheckpointTimer to fetch the missing checkpoint
	rbft.timerMgr.startTimer(fetchCheckpointTimer, event)
}

func (rbft *rbftImpl) stopFetchCheckpointTimer() {
	rbft.timerMgr.stopTimer(fetchCheckpointTimer)
}

func (rbft *rbftImpl) recvFetchCheckpoint(fetch *pb.FetchCheckpoint) consensusEvent {
	if !rbft.inRouters(fetch.GetReplicaHost()) {
		return nil
	}

	signedCheckpoint, ok := rbft.storeMgr.localCheckpoints[fetch.SequenceNumber]
	// If we can find a checkpoint in corresponding height, just send it back.
	if !ok {
		// If we cannot find it, the requesting node might fell behind a lot
		// send back our latest stable-checkpoint-info to help it to recover
		signedCheckpoint, ok = rbft.storeMgr.localCheckpoints[rbft.h]
		if !ok {
			rbft.logger.Warningf("Replica %d cannot find digest of its low watermark %d, "+
				"current node may fall behind", rbft.peerPool.ID, rbft.h)
			return nil
		}
	}

	payload, err := proto.Marshal(signedCheckpoint)
	if err != nil {
		rbft.logger.Errorf("ConsensusMessage_CHECKPOINT Marshal Error: %s", err)
		return nil
	}
	consensusMsg := &pb.ConsensusMessage{
		Type:    pb.Type_SIGNED_CHECKPOINT,
		From:    rbft.peerPool.ID,
		Epoch:   rbft.epoch,
		Payload: payload,
	}
	rbft.peerPool.unicastByHostname(consensusMsg, fetch.GetReplicaHost())

	return nil
}

// checkIfOutOfEpoch track all the messages from nodes in lager epoch than self
func (rbft *rbftImpl) checkIfOutOfEpoch(msg *pb.ConsensusMessage) consensusEvent {
	// as current node has already executed the block no less than epoch number and it is possible that
	// current node will finish the epoch change later, so that we needn't to check epoch here
	if rbft.epoch >= msg.Epoch {
		return nil
	}

	rbft.epochMgr.checkOutOfEpoch[msg.From] = msg.Epoch
	rbft.logger.Debugf("Replica %d in epoch %d received message from %d in epoch %d, now %d messages "+
		"with larger epoch", rbft.peerPool.ID, rbft.epoch, msg.From, msg.Epoch, len(rbft.epochMgr.checkOutOfEpoch))
	if len(rbft.epochMgr.checkOutOfEpoch) >= rbft.oneCorrectQuorum() {
		rbft.epochMgr.checkOutOfEpoch = make(map[uint64]uint64)
		return rbft.initRecovery()
	}

	return nil
}

func (rbft *rbftImpl) turnIntoEpoch() {
	// validator set has been changed, start a new epoch and check new epoch
	epoch := rbft.external.Reconfiguration()

	// set the latest epoch
	rbft.setEpoch(epoch)

	// clear notification storage from lower epoch
	for key, value := range rbft.recoveryMgr.notificationStore {
		if value.Epoch < rbft.epoch {
			delete(rbft.recoveryMgr.notificationStore, key)
		}
	}

	// initial the view, start from view=0
	rbft.setView(uint64(0))
	rbft.persistView(rbft.view)

	// clear view change store
	rbft.vcMgr.viewChangeStore = make(map[vcIdx]*pb.ViewChange)

	// update N/f
	rbft.N = len(rbft.peerPool.routerMap.HostMap)
	rbft.f = (rbft.N - 1) / 3
	rbft.persistN(rbft.N)

	rbft.metrics.clusterSizeGauge.Set(float64(rbft.N))
	rbft.metrics.quorumSizeGauge.Set(float64(rbft.commonCaseQuorum()))

	rbft.logger.Debugf("======== Replica %d turn into a new epoch, epoch=%d/N=%d/view=%d/height=%d.",
		rbft.peerPool.ID, rbft.epoch, rbft.N, rbft.view, rbft.exec.lastExec)
	rbft.logger.Notice(`

  +==============================================+
  |                                              |
  |             RBFT Start New Epoch             |
  |                                              |
  +==============================================+

`)
}

// setEpoch sets the epoch with the epochLock.
func (rbft *rbftImpl) setEpoch(epoch uint64) {
	rbft.epochLock.Lock()
	rbft.epoch = epoch
	rbft.epochLock.Unlock()
	rbft.metrics.epochGauge.Set(float64(epoch))
}

func (rbft *rbftImpl) resetConfigBatchToExecute() {
	rbft.epochMgr.configBatchToExecuteLock.Lock()
	defer rbft.epochMgr.configBatchToExecuteLock.Unlock()
	rbft.epochMgr.configBatchToExecute = uint64(0)
}

func (rbft *rbftImpl) setConfigBatchToExecute(seqNo uint64) {
	rbft.epochMgr.configBatchToExecuteLock.Lock()
	defer rbft.epochMgr.configBatchToExecuteLock.Unlock()
	rbft.epochMgr.configBatchToExecute = seqNo
}

func (rbft *rbftImpl) readConfigBatchToExecute() uint64 {
	rbft.epochMgr.configBatchToExecuteLock.RLock()
	defer rbft.epochMgr.configBatchToExecuteLock.RUnlock()
	return rbft.epochMgr.configBatchToExecute
}
