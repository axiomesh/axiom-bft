// Code generated by MockGen. DO NOT EDIT.
// Source: ../tx_pool.go

// Package txpoolmock is a generated GoMock package.
package txpoolmock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	"github.com/hyperchain/go-hpc-rbft/common/consensus"
	"github.com/hyperchain/go-hpc-rbft/txpool"
)

// MockchainSupport is a mock of chainSupport interface.
type MockchainSupport struct {
	ctrl     *gomock.Controller
	recorder *MockchainSupportMockRecorder
}

// MockchainSupportMockRecorder is the mock recorder for MockchainSupport.
type MockchainSupportMockRecorder struct {
	mock *MockchainSupport
}

// NewMockchainSupport creates a new mock instance.
func NewMockchainSupport(ctrl *gomock.Controller) *MockchainSupport {
	mock := &MockchainSupport{ctrl: ctrl}
	mock.recorder = &MockchainSupportMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockchainSupport) EXPECT() *MockchainSupportMockRecorder {
	return m.recorder
}

// CheckSigns mocks base method.
func (m *MockchainSupport) CheckSigns(txs [][]byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CheckSigns", txs)
}

// CheckSigns indicates an expected call of CheckSigns.
func (mr *MockchainSupportMockRecorder) CheckSigns(txs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckSigns", reflect.TypeOf((*MockchainSupport)(nil).CheckSigns), txs)
}

// IsRequestsExist mocks base method.
func (m *MockchainSupport) IsRequestsExist(txs [][]byte) []bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRequestsExist", txs)
	ret0, _ := ret[0].([]bool)
	return ret0
}

// IsRequestsExist indicates an expected call of IsRequestsExist.
func (mr *MockchainSupportMockRecorder) IsRequestsExist(txs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRequestsExist", reflect.TypeOf((*MockchainSupport)(nil).IsRequestsExist), txs)
}

// MockTxPool is a mock of TxPool interface.
type MockTxPool[T any, Constraint consensus.TXConstraint[T]] struct {
	ctrl     *gomock.Controller
	recorder *MockTxPoolMockRecorder[T, Constraint]
}

// MockTxPoolMockRecorder is the mock recorder for MockTxPool.
type MockTxPoolMockRecorder[T any, Constraint consensus.TXConstraint[T]] struct {
	mock *MockTxPool[T, Constraint]
}

// NewMockTxPool creates a new mock instance.
func NewMockTxPool[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockTxPool[T, Constraint] {
	mock := &MockTxPool[T, Constraint]{ctrl: ctrl}
	mock.recorder = &MockTxPoolMockRecorder[T, Constraint]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTxPool[T, Constraint]) EXPECT() *MockTxPoolMockRecorder[T, Constraint] {
	return m.recorder
}

// AddNewRequests mocks base method.
func (m *MockTxPool[T, Constraint]) AddNewRequests(txs [][]byte, isPrimary, local bool) ([]*txpool.RequestHashBatch[T, Constraint], []string) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddNewRequests", txs, isPrimary, local)
	ret0, _ := ret[0].([]*txpool.RequestHashBatch[T, Constraint])
	ret1, _ := ret[1].([]string)
	return ret0, ret1
}

// AddNewRequests indicates an expected call of AddNewRequests.
func (mr *MockTxPoolMockRecorder[T, Constraint]) AddNewRequests(txs, isPrimary, local interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNewRequests", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).AddNewRequests), txs, isPrimary, local)
}

// FilterOutOfDateRequests mocks base method.
func (m *MockTxPool[T, Constraint]) FilterOutOfDateRequests() ([][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FilterOutOfDateRequests")
	ret0, _ := ret[0].([][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FilterOutOfDateRequests indicates an expected call of FilterOutOfDateRequests.
func (mr *MockTxPoolMockRecorder[T, Constraint]) FilterOutOfDateRequests() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FilterOutOfDateRequests", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).FilterOutOfDateRequests))
}

// GenerateRequestBatch mocks base method.
func (m *MockTxPool[T, Constraint]) GenerateRequestBatch() []*txpool.RequestHashBatch[T, Constraint] {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateRequestBatch")
	ret0, _ := ret[0].([]*txpool.RequestHashBatch[T, Constraint])
	return ret0
}

// GenerateRequestBatch indicates an expected call of GenerateRequestBatch.
func (mr *MockTxPoolMockRecorder[T, Constraint]) GenerateRequestBatch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateRequestBatch", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).GenerateRequestBatch))
}

// GetRequestsByHashList mocks base method.
func (m *MockTxPool[T, Constraint]) GetRequestsByHashList(batchHash string, timestamp int64, hashList, deDuplicateTxHashes []string) ([][]byte, []bool, map[uint64]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestsByHashList", batchHash, timestamp, hashList, deDuplicateTxHashes)
	ret0, _ := ret[0].([][]byte)
	ret1, _ := ret[1].([]bool)
	ret2, _ := ret[2].(map[uint64]string)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// GetRequestsByHashList indicates an expected call of GetRequestsByHashList.
func (mr *MockTxPoolMockRecorder[T, Constraint]) GetRequestsByHashList(batchHash, timestamp, hashList, deDuplicateTxHashes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestsByHashList", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).GetRequestsByHashList), batchHash, timestamp, hashList, deDuplicateTxHashes)
}

// GetUncommittedTransactions mocks base method.
func (m *MockTxPool[T, Constraint]) GetUncommittedTransactions(maxsize uint64) [][]byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUncommittedTransactions", maxsize)
	ret0, _ := ret[0].([][]byte)
	return ret0
}

// GetUncommittedTransactions indicates an expected call of GetUncommittedTransactions.
func (mr *MockTxPoolMockRecorder[T, Constraint]) GetUncommittedTransactions(maxsize interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUncommittedTransactions", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).GetUncommittedTransactions), maxsize)
}

// HasPendingRequestInPool mocks base method.
func (m *MockTxPool[T, Constraint]) HasPendingRequestInPool() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasPendingRequestInPool")
	ret0, _ := ret[0].(bool)
	return ret0
}

// HasPendingRequestInPool indicates an expected call of HasPendingRequestInPool.
func (mr *MockTxPoolMockRecorder[T, Constraint]) HasPendingRequestInPool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasPendingRequestInPool", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).HasPendingRequestInPool))
}

// IsConfigBatch mocks base method.
func (m *MockTxPool[T, Constraint]) IsConfigBatch(batchHash string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConfigBatch", batchHash)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConfigBatch indicates an expected call of IsConfigBatch.
func (mr *MockTxPoolMockRecorder[T, Constraint]) IsConfigBatch(batchHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConfigBatch", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).IsConfigBatch), batchHash)
}

// IsPoolFull mocks base method.
func (m *MockTxPool[T, Constraint]) IsPoolFull() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPoolFull")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsPoolFull indicates an expected call of IsPoolFull.
func (mr *MockTxPoolMockRecorder[T, Constraint]) IsPoolFull() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPoolFull", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).IsPoolFull))
}

// ReConstructBatchByOrder mocks base method.
func (m *MockTxPool[T, Constraint]) ReConstructBatchByOrder(oldBatch *txpool.RequestHashBatch[T, Constraint]) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReConstructBatchByOrder", oldBatch)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReConstructBatchByOrder indicates an expected call of ReConstructBatchByOrder.
func (mr *MockTxPoolMockRecorder[T, Constraint]) ReConstructBatchByOrder(oldBatch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReConstructBatchByOrder", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).ReConstructBatchByOrder), oldBatch)
}

// ReceiveMissingRequests mocks base method.
func (m *MockTxPool[T, Constraint]) ReceiveMissingRequests(batchHash string, txs map[uint64][]byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReceiveMissingRequests", batchHash, txs)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReceiveMissingRequests indicates an expected call of ReceiveMissingRequests.
func (mr *MockTxPoolMockRecorder[T, Constraint]) ReceiveMissingRequests(batchHash, txs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceiveMissingRequests", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).ReceiveMissingRequests), batchHash, txs)
}

// RemoveBatches mocks base method.
func (m *MockTxPool[T, Constraint]) RemoveBatches(hashList []string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RemoveBatches", hashList)
}

// RemoveBatches indicates an expected call of RemoveBatches.
func (mr *MockTxPoolMockRecorder[T, Constraint]) RemoveBatches(hashList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveBatches", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).RemoveBatches), hashList)
}

// Reset mocks base method.
func (m *MockTxPool[T, Constraint]) Reset(saveBatches []string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Reset", saveBatches)
}

// Reset indicates an expected call of Reset.
func (mr *MockTxPoolMockRecorder[T, Constraint]) Reset(saveBatches interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reset", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).Reset), saveBatches)
}

// RestoreOneBatch mocks base method.
func (m *MockTxPool[T, Constraint]) RestoreOneBatch(hash string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RestoreOneBatch", hash)
	ret0, _ := ret[0].(error)
	return ret0
}

// RestoreOneBatch indicates an expected call of RestoreOneBatch.
func (mr *MockTxPoolMockRecorder[T, Constraint]) RestoreOneBatch(hash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestoreOneBatch", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).RestoreOneBatch), hash)
}

// RestorePool mocks base method.
func (m *MockTxPool[T, Constraint]) RestorePool() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RestorePool")
}

// RestorePool indicates an expected call of RestorePool.
func (mr *MockTxPoolMockRecorder[T, Constraint]) RestorePool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RestorePool", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).RestorePool))
}

// SendMissingRequests mocks base method.
func (m *MockTxPool[T, Constraint]) SendMissingRequests(batchHash string, missingHashList map[uint64]string) (map[uint64][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMissingRequests", batchHash, missingHashList)
	ret0, _ := ret[0].(map[uint64][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendMissingRequests indicates an expected call of SendMissingRequests.
func (mr *MockTxPoolMockRecorder[T, Constraint]) SendMissingRequests(batchHash, missingHashList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMissingRequests", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).SendMissingRequests), batchHash, missingHashList)
}

// Start mocks base method.
func (m *MockTxPool[T, Constraint]) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockTxPoolMockRecorder[T, Constraint]) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).Start))
}

// Stop mocks base method.
func (m *MockTxPool[T, Constraint]) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockTxPoolMockRecorder[T, Constraint]) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockTxPool[T, Constraint])(nil).Stop))
}