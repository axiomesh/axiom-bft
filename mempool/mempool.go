package mempool

import (
	"github.com/axiomesh/axiom-bft/common/consensus"
)

// MemPool contains all currently known transactions. Transactions
// enter the pool when they are received from other nodes or submitted
// locally. They are deleted from the pool when they are sure they have
// been included in ledger.
//
// The pool separates transactions being batched and transactions
// waiting to be batched. Transactions would be moved between those
// two states over time. A batch should be generated by consensus
// engine.
//
//go:generate mockgen -destination ./mock_mempool.go -package mempool -source ./mempool.go -typed
type MemPool[T any, Constraint consensus.TXConstraint[T]] interface {
	// GenerateRequestBatch generates a transaction batch and post it
	// to outside if there are transactions in txPool.
	GenerateRequestBatch() []*RequestHashBatch[T, Constraint]

	// AddNewRequests adds transactions into txPool.
	// When current node is primary, judge if we need to generate a batch by batch size.
	// When current node is backup, judge if we can eliminate some missing batches.
	// local indicates if this transaction is froward internally from RPC layer or not.
	// When we receive txs from other nodes(which have been added to other's tx pool) or
	// locally(API layer), we need to check duplication from ledger to avoid duplication
	// with committed txs on ledger.
	// Also, when we receive a tx locally, we need to check if these txs are out-of-date
	// time by time.
	AddNewRequests(txs []*T, isPrimary bool, local, isReplace bool) ([]*RequestHashBatch[T, Constraint], []string)

	// RemoveBatches removes several batches by given digests of
	// transaction batches from the pool(batchedTxs).
	RemoveBatches(hashList []string)

	// IsPoolFull check if txPool is full which means if number of all cached txs
	// has exceeded the limited poolSize.
	IsPoolFull() bool

	// HasPendingRequestInPool checks if there is non-batched tx(s) in tx pool or not
	HasPendingRequestInPool() bool

	// RestoreOneBatch moves one batch from batchStore back to non-batched txs.
	RestoreOneBatch(hash string) error

	// GetRequestsByHashList returns the transaction list corresponding to the given hash list.
	// When replicas receive hashList from primary, they need to generate a totally same
	// batch to primary generated one. deDuplicateTxHashes specifies some txs which should
	// be excluded from duplicate rules.
	// 1. If this batch has been batched, just return its transactions without error.
	// 2. If we have checked this batch and found we were missing some transactions, just
	//    return the same missingTxsHash as before without error.
	// 3. If one transaction in hashList has been batched before in another batch,
	//    return ErrDuplicateTx
	// 4. If we miss some transactions, we need to fetch these transactions from primary,
	//    and return missingTxsHash without error
	// 5. If this node get all transactions from pool, generate a batch and return its
	//    transactions without error
	GetRequestsByHashList(batchHash string, timestamp int64, hashList []string, deDuplicateTxHashes []string) (txs []*T, list []bool, missingTxsHash map[uint64]string, err error)

	// SendMissingRequests used by primary to find one batch in batchStore which should contain
	// txs which are specified in missingHashList.
	// 1. If there is no such batch, return ErrNoBatch.
	// 2. If there is such a batch, but it doesn't contain all txs in missingHashList,
	//    return ErrMismatch.
	// 3. If there is such a batch, and contains all needed txs, returns all needed txs by
	//    order.
	SendMissingRequests(batchHash string, missingHashList map[uint64]string) (txs map[uint64]*T, err error)

	// ReceiveMissingRequests receives txs fetched from primary and add txs to txPool
	ReceiveMissingRequests(batchHash string, txs map[uint64]*T) error

	// FilterOutOfDateRequests get the remained local txs in nonBatchedTxs which are
	// "out-of-date" by tolerance time.
	FilterOutOfDateRequests() ([]*T, error)

	// RestorePool move all batched txs back to non-batched tx which should
	// only be used after abnormal recovery.
	RestorePool()

	// ReConstructBatchByOrder reconstruct batch from empty txPool by order, must be called after RestorePool.
	ReConstructBatchByOrder(oldBatch *RequestHashBatch[T, Constraint]) (deDuplicateTxHashes []string, err error)

	// Reset clears all cached txs in txPool and start with a pure empty environment,
	// except batches in saveBatches and local non-batched-txs that not included in ledger.
	Reset(saveBatches []string)

	// GetUncommittedTransactions returns all transactions that have not been committed to the ledger
	GetUncommittedTransactions(maxsize uint64) []*T

	// Start starts txPool service
	Start() error

	// Stop stops txPool service
	Stop()

	Init(selfID uint64) error

	External[T, Constraint]
}

// External interface called concurrently by client.
type External[T any, Constraint consensus.TXConstraint[T]] interface {
	// RemoveTimeoutRequests get the remained local txs in timeoutIndex and removeTxs in memPool by tolerance time.
	RemoveTimeoutRequests() (uint64, error)

	// GetPendingNonceByAccount returns pendingNonce by given account.
	GetPendingNonceByAccount(account string) uint64

	GetPendingTxByHash(hash string) *T
}

// NewMempool returns the mempool instance.
func NewMempool[T any, Constraint consensus.TXConstraint[T]](config Config) MemPool[T, Constraint] {
	return newMempoolImpl[T, Constraint](config)
}
