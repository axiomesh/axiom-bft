package rbft

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/axiomesh/axiom-bft/common/consensus"
)

func TestBatchMgr_startBatchTimer(t *testing.T) {
	_, rbfts := newBasicClusterInstance[consensus.FltTransaction, *consensus.FltTransaction]()
	assert.False(t, rbfts[0].timerMgr.getTimer(batchTimer))
	assert.False(t, rbfts[0].batchMgr.isBatchTimerActive())
	rbfts[0].startBatchTimer()
	assert.True(t, rbfts[0].timerMgr.getTimer(batchTimer))
	assert.True(t, rbfts[0].batchMgr.isBatchTimerActive())
}

// Test for only this function
func TestBatchMgr_maybeSendPrePrepare(t *testing.T) {
	_, rbfts := newBasicClusterInstance[consensus.FltTransaction, *consensus.FltTransaction]()

	// Set a Batch
	txx41 := newTx()
	batchTmp41 := &RequestBatch[consensus.FltTransaction, *consensus.FltTransaction]{
		RequestHashList: []string{"tx-hash-41"},
		RequestList:     []*consensus.FltTransaction{txx41},
		Timestamp:       time.Now().UnixNano(),
		LocalList:       []bool{true},
		BatchHash:       "test digest 41",
	}
	tx42 := newTx()
	batchTmp42 := &RequestBatch[consensus.FltTransaction, *consensus.FltTransaction]{
		RequestHashList: []string{"tx-hash-42"},
		RequestList:     []*consensus.FltTransaction{tx42},
		Timestamp:       time.Now().UnixNano(),
		LocalList:       []bool{true},
		BatchHash:       "test digest 42",
	}

	// Be out of range, need usage of catch
	// And, it is the first one to be in catch
	rbfts[0].batchMgr.setSeqNo(40)
	rbfts[0].maybeSendPrePrepare(batchTmp41, false)
	rbfts[0].maybeSendPrePrepare(batchTmp42, false)
	assert.Equal(t, batchTmp41, rbfts[0].batchMgr.cacheBatch[0])
	assert.Equal(t, batchTmp42, rbfts[0].batchMgr.cacheBatch[1])

	// Be in the range
	// to find in catch
	// Now, rbft.batchMgr.cacheBatch[0] has already store a value
	// Set rbft.h 10, 10~50
	rbfts[0].moveWatermarks(10, false)
	rbfts[0].maybeSendPrePrepare(nil, true)
	// assume that
	assert.Equal(t, batchTmp41, rbfts[0].storeMgr.batchStore[batchTmp41.BatchHash])
	assert.Equal(t, batchTmp42, rbfts[0].storeMgr.batchStore[batchTmp42.BatchHash])
}

func TestBatchMgr_findNextPrepareBatch(t *testing.T) {
	_, rbfts := newBasicClusterInstance[consensus.FltTransaction, *consensus.FltTransaction]()

	// Struct of certTmp which stored in rbft.storeMgr.certStore
	prePrepareTmp := &consensus.PrePrepare{
		ReplicaId:      2,
		View:           0,
		SequenceNumber: 20,
		BatchDigest:    "msg",
		HashBatch:      &consensus.HashBatch{Timestamp: 10086},
	}
	prePareTmp := consensus.Prepare{
		ReplicaId:      3,
		View:           0,
		SequenceNumber: 20,
		BatchDigest:    "msg",
	}
	commitTmp := consensus.Commit{
		ReplicaId:      4,
		View:           0,
		SequenceNumber: 20,
		BatchDigest:    "msg",
	}
	msgIDTmp := msgID{
		v: 0,
		n: 20,
		d: "msg",
	}

	// Define an empty cert first
	certTmp := &msgCert{
		prePrepare:  nil,
		sentPrepare: false,
		prepare:     nil, // map[consensus.Prepare]bool{prePareTmp: true},
		sentCommit:  false,
		commit:      nil, // map[consensus.Commit]bool{commitTmp: true},
		sentExecute: false,
	}
	rbfts[0].storeMgr.certStore[msgIDTmp] = certTmp

	t.Run("When view is incorrect, exit with nil, without any change", func(t *testing.T) {
		rbfts[0].setView(1)
		assert.Nil(t, rbfts[0].findNextPrepareBatch(context.TODO(), 0, 20, "msg"))
		rbfts[0].setView(0)
	})

	t.Run("When prePrepare is nil, exit with nil, without any change", func(t *testing.T) {
		assert.Nil(t, rbfts[0].findNextPrepareBatch(context.TODO(), 0, 20, "msg"))
		certTmp.prePrepare = prePrepareTmp
	})

	t.Run("If replica is in stateUpdate, exit with nil, without any change", func(t *testing.T) {
		rbfts[0].on(SkipInProgress)
		assert.Nil(t, rbfts[0].findNextPrepareBatch(context.TODO(), 0, 20, "msg"))
		rbfts[0].off(SkipInProgress)
	})

	t.Run("Normal case, there are no batches in storeMgr", func(t *testing.T) {
		// store the HashBatch which was input by certTmp
		certTmp.prepare = map[string]*consensus.Prepare{prePareTmp.ID(): &prePareTmp}
		certTmp.commit = map[string]*consensus.Commit{commitTmp.ID(): &commitTmp}

		assert.Nil(t, rbfts[0].findNextPrepareBatch(context.TODO(), 0, 20, "msg"))

		// verified key: Timestamp
		assert.Equal(t, int64(10086), rbfts[0].storeMgr.outstandingReqBatches["msg"].Timestamp)
		assert.Equal(t, int64(10086), rbfts[0].storeMgr.batchStore["msg"].Timestamp)
		assert.Equal(t, true, rbfts[0].storeMgr.certStore[msgIDTmp].sentPrepare)

		// To resend commit
		rbfts[0].storeMgr.certStore[msgIDTmp].sentPrepare = false
		assert.Nil(t, rbfts[0].findNextPrepareBatch(context.TODO(), 0, 20, "msg"))
		assert.Equal(t, true, rbfts[0].storeMgr.certStore[msgIDTmp].sentPrepare)
		// LastBlockDigest == ""
		prePrepareTmpNil := &consensus.PrePrepare{
			ReplicaId:      2,
			View:           0,
			SequenceNumber: 30,
			BatchDigest:    "",
			HashBatch:      &consensus.HashBatch{Timestamp: 10086},
		}
		prePareTmpNil := consensus.Prepare{
			ReplicaId:      3,
			View:           0,
			SequenceNumber: 30,
			BatchDigest:    "",
		}
		commitTmpNil := consensus.Commit{
			ReplicaId:      4,
			View:           0,
			SequenceNumber: 30,
			BatchDigest:    "",
		}
		msgIDTmpNil := msgID{
			v: 0,
			n: 30,
			d: "",
		}
		certTmpNil := &msgCert{
			prePrepare:  prePrepareTmpNil,
			sentPrepare: false,
			prepare:     map[string]*consensus.Prepare{prePareTmpNil.ID(): &prePareTmpNil},
			sentCommit:  false,
			commit:      map[string]*consensus.Commit{commitTmpNil.ID(): &commitTmpNil},
			sentExecute: false,
		}
		rbfts[0].setView(0)
		rbfts[0].storeMgr.certStore[msgIDTmpNil] = certTmpNil
		rbfts[0].storeMgr.certStore[msgIDTmpNil].sentPrepare = false
		_ = rbfts[0].findNextPrepareBatch(context.TODO(), 0, 30, "")
		assert.Equal(t, true, rbfts[0].storeMgr.certStore[msgIDTmpNil].sentPrepare)
		assert.Equal(t, true, rbfts[0].storeMgr.certStore[msgIDTmpNil].sentPrepare)

		prePrepareConfBatch := &consensus.PrePrepare{
			ReplicaId:      2,
			View:           0,
			SequenceNumber: 35,
			BatchDigest:    "conf-batch-hash",
			HashBatch:      &consensus.HashBatch{Timestamp: 10086},
		}
		msgIDConfBatch := msgID{
			v: 0,
			n: 35,
			d: "conf-batch-hash",
		}
		certConfBatch := &msgCert{
			prePrepare:  prePrepareConfBatch,
			sentPrepare: false,
			prepare:     map[string]*consensus.Prepare{prePareTmpNil.ID(): &prePareTmpNil},
			sentCommit:  false,
			commit:      map[string]*consensus.Commit{commitTmpNil.ID(): &commitTmpNil},
			sentExecute: false,
		}
		rbfts[0].storeMgr.certStore[msgIDConfBatch] = certConfBatch
	})
}
