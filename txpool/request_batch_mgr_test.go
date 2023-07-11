package txpool

import (
	"testing"

	"github.com/hyperchain/go-hpc-rbft/v2/common/consensus"

	"github.com/stretchr/testify/assert"
)

func TestRequestHashBatch_IsConfBatch(t *testing.T) {
	tx1 := &consensus.Transaction{TxType: consensus.Transaction_CTX}
	txBytes1, err := tx1.Marshal()
	assert.Nil(t, err)
	batch1 := &RequestHashBatch{
		BatchHash:  "",
		TxHashList: nil,
		TxList:     [][]byte{txBytes1},
		LocalList:  nil,
		TimeList:   nil,
		Timestamp:  0,
	}
	flag1 := batch1.IsConfBatch()

	tx2 := &consensus.Transaction{TxType: consensus.Transaction_NTX}
	txBytes2, err := tx2.Marshal()
	assert.Nil(t, err)
	batch2 := &RequestHashBatch{
		BatchHash:  "",
		TxHashList: nil,
		TxList:     [][]byte{txBytes2},
		LocalList:  nil,
		TimeList:   nil,
		Timestamp:  0,
	}
	flag2 := batch2.IsConfBatch()

	assert.Equal(t, flag1, false)
	assert.Equal(t, flag2, false)
}
