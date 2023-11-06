// Code generated by MockGen. DO NOT EDIT.
// Source: ./node.go
//
// Generated by this command:
//
//	mockgen -destination ./mock_node.go -package rbft -source ./node.go -typed
//

// Package rbft is a generated GoMock package.
package rbft

import (
	context "context"
	reflect "reflect"

	consensus "github.com/axiomesh/axiom-bft/common/consensus"
	txpool "github.com/axiomesh/axiom-bft/txpool"
	types "github.com/axiomesh/axiom-bft/types"
	gomock "go.uber.org/mock/gomock"
)

// MockNode is a mock of Node interface.
type MockNode[T any, Constraint consensus.TXConstraint[T]] struct {
	ctrl     *gomock.Controller
	recorder *MockNodeMockRecorder[T, Constraint]
}

// MockNodeMockRecorder is the mock recorder for MockNode.
type MockNodeMockRecorder[T any, Constraint consensus.TXConstraint[T]] struct {
	mock *MockNode[T, Constraint]
}

// NewMockNode creates a new mock instance.
func NewMockNode[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockNode[T, Constraint] {
	mock := &MockNode[T, Constraint]{ctrl: ctrl}
	mock.recorder = &MockNodeMockRecorder[T, Constraint]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNode[T, Constraint]) EXPECT() *MockNodeMockRecorder[T, Constraint] {
	return m.recorder
}

// GetAccountPoolMeta mocks base method.
func (m *MockNode[T, Constraint]) GetAccountPoolMeta(account string, full bool) *txpool.AccountMeta[T, Constraint] {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountPoolMeta", account, full)
	ret0, _ := ret[0].(*txpool.AccountMeta[T, Constraint])
	return ret0
}

// GetAccountPoolMeta indicates an expected call of GetAccountPoolMeta.
func (mr *MockNodeMockRecorder[T, Constraint]) GetAccountPoolMeta(account, full any) *NodeGetAccountPoolMetaCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountPoolMeta", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetAccountPoolMeta), account, full)
	return &NodeGetAccountPoolMetaCall[T, Constraint]{Call: call}
}

// NodeGetAccountPoolMetaCall wrap *gomock.Call
type NodeGetAccountPoolMetaCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetAccountPoolMetaCall[T, Constraint]) Return(arg0 *txpool.AccountMeta[T, Constraint]) *NodeGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetAccountPoolMetaCall[T, Constraint]) Do(f func(string, bool) *txpool.AccountMeta[T, Constraint]) *NodeGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetAccountPoolMetaCall[T, Constraint]) DoAndReturn(f func(string, bool) *txpool.AccountMeta[T, Constraint]) *NodeGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetLowWatermark mocks base method.
func (m *MockNode[T, Constraint]) GetLowWatermark() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLowWatermark")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetLowWatermark indicates an expected call of GetLowWatermark.
func (mr *MockNodeMockRecorder[T, Constraint]) GetLowWatermark() *NodeGetLowWatermarkCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLowWatermark", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetLowWatermark))
	return &NodeGetLowWatermarkCall[T, Constraint]{Call: call}
}

// NodeGetLowWatermarkCall wrap *gomock.Call
type NodeGetLowWatermarkCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetLowWatermarkCall[T, Constraint]) Return(arg0 uint64) *NodeGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetLowWatermarkCall[T, Constraint]) Do(f func() uint64) *NodeGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetLowWatermarkCall[T, Constraint]) DoAndReturn(f func() uint64) *NodeGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPendingTxByHash mocks base method.
func (m *MockNode[T, Constraint]) GetPendingTxByHash(hash string) *T {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPendingTxByHash", hash)
	ret0, _ := ret[0].(*T)
	return ret0
}

// GetPendingTxByHash indicates an expected call of GetPendingTxByHash.
func (mr *MockNodeMockRecorder[T, Constraint]) GetPendingTxByHash(hash any) *NodeGetPendingTxByHashCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPendingTxByHash", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetPendingTxByHash), hash)
	return &NodeGetPendingTxByHashCall[T, Constraint]{Call: call}
}

// NodeGetPendingTxByHashCall wrap *gomock.Call
type NodeGetPendingTxByHashCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetPendingTxByHashCall[T, Constraint]) Return(arg0 *T) *NodeGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetPendingTxByHashCall[T, Constraint]) Do(f func(string) *T) *NodeGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetPendingTxByHashCall[T, Constraint]) DoAndReturn(f func(string) *T) *NodeGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPendingTxCountByAccount mocks base method.
func (m *MockNode[T, Constraint]) GetPendingTxCountByAccount(account string) uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPendingTxCountByAccount", account)
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetPendingTxCountByAccount indicates an expected call of GetPendingTxCountByAccount.
func (mr *MockNodeMockRecorder[T, Constraint]) GetPendingTxCountByAccount(account any) *NodeGetPendingTxCountByAccountCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPendingTxCountByAccount", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetPendingTxCountByAccount), account)
	return &NodeGetPendingTxCountByAccountCall[T, Constraint]{Call: call}
}

// NodeGetPendingTxCountByAccountCall wrap *gomock.Call
type NodeGetPendingTxCountByAccountCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetPendingTxCountByAccountCall[T, Constraint]) Return(arg0 uint64) *NodeGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetPendingTxCountByAccountCall[T, Constraint]) Do(f func(string) uint64) *NodeGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetPendingTxCountByAccountCall[T, Constraint]) DoAndReturn(f func(string) uint64) *NodeGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPoolMeta mocks base method.
func (m *MockNode[T, Constraint]) GetPoolMeta(full bool) *txpool.Meta[T, Constraint] {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPoolMeta", full)
	ret0, _ := ret[0].(*txpool.Meta[T, Constraint])
	return ret0
}

// GetPoolMeta indicates an expected call of GetPoolMeta.
func (mr *MockNodeMockRecorder[T, Constraint]) GetPoolMeta(full any) *NodeGetPoolMetaCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPoolMeta", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetPoolMeta), full)
	return &NodeGetPoolMetaCall[T, Constraint]{Call: call}
}

// NodeGetPoolMetaCall wrap *gomock.Call
type NodeGetPoolMetaCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetPoolMetaCall[T, Constraint]) Return(arg0 *txpool.Meta[T, Constraint]) *NodeGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetPoolMetaCall[T, Constraint]) Do(f func(bool) *txpool.Meta[T, Constraint]) *NodeGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetPoolMetaCall[T, Constraint]) DoAndReturn(f func(bool) *txpool.Meta[T, Constraint]) *NodeGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetTotalPendingTxCount mocks base method.
func (m *MockNode[T, Constraint]) GetTotalPendingTxCount() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTotalPendingTxCount")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetTotalPendingTxCount indicates an expected call of GetTotalPendingTxCount.
func (mr *MockNodeMockRecorder[T, Constraint]) GetTotalPendingTxCount() *NodeGetTotalPendingTxCountCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTotalPendingTxCount", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetTotalPendingTxCount))
	return &NodeGetTotalPendingTxCountCall[T, Constraint]{Call: call}
}

// NodeGetTotalPendingTxCountCall wrap *gomock.Call
type NodeGetTotalPendingTxCountCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetTotalPendingTxCountCall[T, Constraint]) Return(arg0 uint64) *NodeGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetTotalPendingTxCountCall[T, Constraint]) Do(f func() uint64) *NodeGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetTotalPendingTxCountCall[T, Constraint]) DoAndReturn(f func() uint64) *NodeGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetUncommittedTransactions mocks base method.
func (m *MockNode[T, Constraint]) GetUncommittedTransactions(maxsize uint64) []*T {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUncommittedTransactions", maxsize)
	ret0, _ := ret[0].([]*T)
	return ret0
}

// GetUncommittedTransactions indicates an expected call of GetUncommittedTransactions.
func (mr *MockNodeMockRecorder[T, Constraint]) GetUncommittedTransactions(maxsize any) *NodeGetUncommittedTransactionsCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUncommittedTransactions", reflect.TypeOf((*MockNode[T, Constraint])(nil).GetUncommittedTransactions), maxsize)
	return &NodeGetUncommittedTransactionsCall[T, Constraint]{Call: call}
}

// NodeGetUncommittedTransactionsCall wrap *gomock.Call
type NodeGetUncommittedTransactionsCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeGetUncommittedTransactionsCall[T, Constraint]) Return(arg0 []*T) *NodeGetUncommittedTransactionsCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeGetUncommittedTransactionsCall[T, Constraint]) Do(f func(uint64) []*T) *NodeGetUncommittedTransactionsCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeGetUncommittedTransactionsCall[T, Constraint]) DoAndReturn(f func(uint64) []*T) *NodeGetUncommittedTransactionsCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Init mocks base method.
func (m *MockNode[T, Constraint]) Init() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Init")
	ret0, _ := ret[0].(error)
	return ret0
}

// Init indicates an expected call of Init.
func (mr *MockNodeMockRecorder[T, Constraint]) Init() *NodeInitCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Init", reflect.TypeOf((*MockNode[T, Constraint])(nil).Init))
	return &NodeInitCall[T, Constraint]{Call: call}
}

// NodeInitCall wrap *gomock.Call
type NodeInitCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeInitCall[T, Constraint]) Return(arg0 error) *NodeInitCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeInitCall[T, Constraint]) Do(f func() error) *NodeInitCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeInitCall[T, Constraint]) DoAndReturn(f func() error) *NodeInitCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Propose mocks base method.
func (m *MockNode[T, Constraint]) Propose(requests []*T, local bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Propose", requests, local)
	ret0, _ := ret[0].(error)
	return ret0
}

// Propose indicates an expected call of Propose.
func (mr *MockNodeMockRecorder[T, Constraint]) Propose(requests, local any) *NodeProposeCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Propose", reflect.TypeOf((*MockNode[T, Constraint])(nil).Propose), requests, local)
	return &NodeProposeCall[T, Constraint]{Call: call}
}

// NodeProposeCall wrap *gomock.Call
type NodeProposeCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeProposeCall[T, Constraint]) Return(arg0 error) *NodeProposeCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeProposeCall[T, Constraint]) Do(f func([]*T, bool) error) *NodeProposeCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeProposeCall[T, Constraint]) DoAndReturn(f func([]*T, bool) error) *NodeProposeCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReportExecuted mocks base method.
func (m *MockNode[T, Constraint]) ReportExecuted(state *types.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportExecuted", state)
}

// ReportExecuted indicates an expected call of ReportExecuted.
func (mr *MockNodeMockRecorder[T, Constraint]) ReportExecuted(state any) *NodeReportExecutedCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockNode[T, Constraint])(nil).ReportExecuted), state)
	return &NodeReportExecutedCall[T, Constraint]{Call: call}
}

// NodeReportExecutedCall wrap *gomock.Call
type NodeReportExecutedCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeReportExecutedCall[T, Constraint]) Return() *NodeReportExecutedCall[T, Constraint] {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeReportExecutedCall[T, Constraint]) Do(f func(*types.ServiceState)) *NodeReportExecutedCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeReportExecutedCall[T, Constraint]) DoAndReturn(f func(*types.ServiceState)) *NodeReportExecutedCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReportStateUpdated mocks base method.
func (m *MockNode[T, Constraint]) ReportStateUpdated(state *types.ServiceSyncState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated.
func (mr *MockNodeMockRecorder[T, Constraint]) ReportStateUpdated(state any) *NodeReportStateUpdatedCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockNode[T, Constraint])(nil).ReportStateUpdated), state)
	return &NodeReportStateUpdatedCall[T, Constraint]{Call: call}
}

// NodeReportStateUpdatedCall wrap *gomock.Call
type NodeReportStateUpdatedCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeReportStateUpdatedCall[T, Constraint]) Return() *NodeReportStateUpdatedCall[T, Constraint] {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeReportStateUpdatedCall[T, Constraint]) Do(f func(*types.ServiceSyncState)) *NodeReportStateUpdatedCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeReportStateUpdatedCall[T, Constraint]) DoAndReturn(f func(*types.ServiceSyncState)) *NodeReportStateUpdatedCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReportStateUpdatingBatches mocks base method.
func (m *MockNode[T, Constraint]) ReportStateUpdatingBatches(committedTxHashList []string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdatingBatches", committedTxHashList)
}

// ReportStateUpdatingBatches indicates an expected call of ReportStateUpdatingBatches.
func (mr *MockNodeMockRecorder[T, Constraint]) ReportStateUpdatingBatches(committedTxHashList any) *NodeReportStateUpdatingBatchesCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdatingBatches", reflect.TypeOf((*MockNode[T, Constraint])(nil).ReportStateUpdatingBatches), committedTxHashList)
	return &NodeReportStateUpdatingBatchesCall[T, Constraint]{Call: call}
}

// NodeReportStateUpdatingBatchesCall wrap *gomock.Call
type NodeReportStateUpdatingBatchesCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeReportStateUpdatingBatchesCall[T, Constraint]) Return() *NodeReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeReportStateUpdatingBatchesCall[T, Constraint]) Do(f func([]string)) *NodeReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeReportStateUpdatingBatchesCall[T, Constraint]) DoAndReturn(f func([]string)) *NodeReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Start mocks base method.
func (m *MockNode[T, Constraint]) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockNodeMockRecorder[T, Constraint]) Start() *NodeStartCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockNode[T, Constraint])(nil).Start))
	return &NodeStartCall[T, Constraint]{Call: call}
}

// NodeStartCall wrap *gomock.Call
type NodeStartCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeStartCall[T, Constraint]) Return(arg0 error) *NodeStartCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeStartCall[T, Constraint]) Do(f func() error) *NodeStartCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeStartCall[T, Constraint]) DoAndReturn(f func() error) *NodeStartCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Status mocks base method.
func (m *MockNode[T, Constraint]) Status() NodeStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(NodeStatus)
	return ret0
}

// Status indicates an expected call of Status.
func (mr *MockNodeMockRecorder[T, Constraint]) Status() *NodeStatusCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockNode[T, Constraint])(nil).Status))
	return &NodeStatusCall[T, Constraint]{Call: call}
}

// NodeStatusCall wrap *gomock.Call
type NodeStatusCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeStatusCall[T, Constraint]) Return(arg0 NodeStatus) *NodeStatusCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeStatusCall[T, Constraint]) Do(f func() NodeStatus) *NodeStatusCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeStatusCall[T, Constraint]) DoAndReturn(f func() NodeStatus) *NodeStatusCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Step mocks base method.
func (m *MockNode[T, Constraint]) Step(ctx context.Context, msg *consensus.ConsensusMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Step", ctx, msg)
}

// Step indicates an expected call of Step.
func (mr *MockNodeMockRecorder[T, Constraint]) Step(ctx, msg any) *NodeStepCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Step", reflect.TypeOf((*MockNode[T, Constraint])(nil).Step), ctx, msg)
	return &NodeStepCall[T, Constraint]{Call: call}
}

// NodeStepCall wrap *gomock.Call
type NodeStepCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeStepCall[T, Constraint]) Return() *NodeStepCall[T, Constraint] {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeStepCall[T, Constraint]) Do(f func(context.Context, *consensus.ConsensusMessage)) *NodeStepCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeStepCall[T, Constraint]) DoAndReturn(f func(context.Context, *consensus.ConsensusMessage)) *NodeStepCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Stop mocks base method.
func (m *MockNode[T, Constraint]) Stop() []*T {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].([]*T)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockNodeMockRecorder[T, Constraint]) Stop() *NodeStopCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockNode[T, Constraint])(nil).Stop))
	return &NodeStopCall[T, Constraint]{Call: call}
}

// NodeStopCall wrap *gomock.Call
type NodeStopCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *NodeStopCall[T, Constraint]) Return(arg0 []*T) *NodeStopCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *NodeStopCall[T, Constraint]) Do(f func() []*T) *NodeStopCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *NodeStopCall[T, Constraint]) DoAndReturn(f func() []*T) *NodeStopCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockExternal is a mock of External interface.
type MockExternal[T any, Constraint consensus.TXConstraint[T]] struct {
	ctrl     *gomock.Controller
	recorder *MockExternalMockRecorder[T, Constraint]
}

// MockExternalMockRecorder is the mock recorder for MockExternal.
type MockExternalMockRecorder[T any, Constraint consensus.TXConstraint[T]] struct {
	mock *MockExternal[T, Constraint]
}

// NewMockExternal creates a new mock instance.
func NewMockExternal[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockExternal[T, Constraint] {
	mock := &MockExternal[T, Constraint]{ctrl: ctrl}
	mock.recorder = &MockExternalMockRecorder[T, Constraint]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockExternal[T, Constraint]) EXPECT() *MockExternalMockRecorder[T, Constraint] {
	return m.recorder
}

// GetAccountPoolMeta mocks base method.
func (m *MockExternal[T, Constraint]) GetAccountPoolMeta(account string, full bool) *txpool.AccountMeta[T, Constraint] {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccountPoolMeta", account, full)
	ret0, _ := ret[0].(*txpool.AccountMeta[T, Constraint])
	return ret0
}

// GetAccountPoolMeta indicates an expected call of GetAccountPoolMeta.
func (mr *MockExternalMockRecorder[T, Constraint]) GetAccountPoolMeta(account, full any) *ExternalGetAccountPoolMetaCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccountPoolMeta", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetAccountPoolMeta), account, full)
	return &ExternalGetAccountPoolMetaCall[T, Constraint]{Call: call}
}

// ExternalGetAccountPoolMetaCall wrap *gomock.Call
type ExternalGetAccountPoolMetaCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetAccountPoolMetaCall[T, Constraint]) Return(arg0 *txpool.AccountMeta[T, Constraint]) *ExternalGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetAccountPoolMetaCall[T, Constraint]) Do(f func(string, bool) *txpool.AccountMeta[T, Constraint]) *ExternalGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetAccountPoolMetaCall[T, Constraint]) DoAndReturn(f func(string, bool) *txpool.AccountMeta[T, Constraint]) *ExternalGetAccountPoolMetaCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetLowWatermark mocks base method.
func (m *MockExternal[T, Constraint]) GetLowWatermark() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLowWatermark")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetLowWatermark indicates an expected call of GetLowWatermark.
func (mr *MockExternalMockRecorder[T, Constraint]) GetLowWatermark() *ExternalGetLowWatermarkCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLowWatermark", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetLowWatermark))
	return &ExternalGetLowWatermarkCall[T, Constraint]{Call: call}
}

// ExternalGetLowWatermarkCall wrap *gomock.Call
type ExternalGetLowWatermarkCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetLowWatermarkCall[T, Constraint]) Return(arg0 uint64) *ExternalGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetLowWatermarkCall[T, Constraint]) Do(f func() uint64) *ExternalGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetLowWatermarkCall[T, Constraint]) DoAndReturn(f func() uint64) *ExternalGetLowWatermarkCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPendingTxByHash mocks base method.
func (m *MockExternal[T, Constraint]) GetPendingTxByHash(hash string) *T {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPendingTxByHash", hash)
	ret0, _ := ret[0].(*T)
	return ret0
}

// GetPendingTxByHash indicates an expected call of GetPendingTxByHash.
func (mr *MockExternalMockRecorder[T, Constraint]) GetPendingTxByHash(hash any) *ExternalGetPendingTxByHashCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPendingTxByHash", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetPendingTxByHash), hash)
	return &ExternalGetPendingTxByHashCall[T, Constraint]{Call: call}
}

// ExternalGetPendingTxByHashCall wrap *gomock.Call
type ExternalGetPendingTxByHashCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetPendingTxByHashCall[T, Constraint]) Return(arg0 *T) *ExternalGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetPendingTxByHashCall[T, Constraint]) Do(f func(string) *T) *ExternalGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetPendingTxByHashCall[T, Constraint]) DoAndReturn(f func(string) *T) *ExternalGetPendingTxByHashCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPendingTxCountByAccount mocks base method.
func (m *MockExternal[T, Constraint]) GetPendingTxCountByAccount(account string) uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPendingTxCountByAccount", account)
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetPendingTxCountByAccount indicates an expected call of GetPendingTxCountByAccount.
func (mr *MockExternalMockRecorder[T, Constraint]) GetPendingTxCountByAccount(account any) *ExternalGetPendingTxCountByAccountCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPendingTxCountByAccount", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetPendingTxCountByAccount), account)
	return &ExternalGetPendingTxCountByAccountCall[T, Constraint]{Call: call}
}

// ExternalGetPendingTxCountByAccountCall wrap *gomock.Call
type ExternalGetPendingTxCountByAccountCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetPendingTxCountByAccountCall[T, Constraint]) Return(arg0 uint64) *ExternalGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetPendingTxCountByAccountCall[T, Constraint]) Do(f func(string) uint64) *ExternalGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetPendingTxCountByAccountCall[T, Constraint]) DoAndReturn(f func(string) uint64) *ExternalGetPendingTxCountByAccountCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPoolMeta mocks base method.
func (m *MockExternal[T, Constraint]) GetPoolMeta(full bool) *txpool.Meta[T, Constraint] {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPoolMeta", full)
	ret0, _ := ret[0].(*txpool.Meta[T, Constraint])
	return ret0
}

// GetPoolMeta indicates an expected call of GetPoolMeta.
func (mr *MockExternalMockRecorder[T, Constraint]) GetPoolMeta(full any) *ExternalGetPoolMetaCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPoolMeta", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetPoolMeta), full)
	return &ExternalGetPoolMetaCall[T, Constraint]{Call: call}
}

// ExternalGetPoolMetaCall wrap *gomock.Call
type ExternalGetPoolMetaCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetPoolMetaCall[T, Constraint]) Return(arg0 *txpool.Meta[T, Constraint]) *ExternalGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetPoolMetaCall[T, Constraint]) Do(f func(bool) *txpool.Meta[T, Constraint]) *ExternalGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetPoolMetaCall[T, Constraint]) DoAndReturn(f func(bool) *txpool.Meta[T, Constraint]) *ExternalGetPoolMetaCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetTotalPendingTxCount mocks base method.
func (m *MockExternal[T, Constraint]) GetTotalPendingTxCount() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTotalPendingTxCount")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetTotalPendingTxCount indicates an expected call of GetTotalPendingTxCount.
func (mr *MockExternalMockRecorder[T, Constraint]) GetTotalPendingTxCount() *ExternalGetTotalPendingTxCountCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTotalPendingTxCount", reflect.TypeOf((*MockExternal[T, Constraint])(nil).GetTotalPendingTxCount))
	return &ExternalGetTotalPendingTxCountCall[T, Constraint]{Call: call}
}

// ExternalGetTotalPendingTxCountCall wrap *gomock.Call
type ExternalGetTotalPendingTxCountCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalGetTotalPendingTxCountCall[T, Constraint]) Return(arg0 uint64) *ExternalGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalGetTotalPendingTxCountCall[T, Constraint]) Do(f func() uint64) *ExternalGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalGetTotalPendingTxCountCall[T, Constraint]) DoAndReturn(f func() uint64) *ExternalGetTotalPendingTxCountCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReportStateUpdatingBatches mocks base method.
func (m *MockExternal[T, Constraint]) ReportStateUpdatingBatches(committedTxHashList []string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdatingBatches", committedTxHashList)
}

// ReportStateUpdatingBatches indicates an expected call of ReportStateUpdatingBatches.
func (mr *MockExternalMockRecorder[T, Constraint]) ReportStateUpdatingBatches(committedTxHashList any) *ExternalReportStateUpdatingBatchesCall[T, Constraint] {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdatingBatches", reflect.TypeOf((*MockExternal[T, Constraint])(nil).ReportStateUpdatingBatches), committedTxHashList)
	return &ExternalReportStateUpdatingBatchesCall[T, Constraint]{Call: call}
}

// ExternalReportStateUpdatingBatchesCall wrap *gomock.Call
type ExternalReportStateUpdatingBatchesCall[T any, Constraint consensus.TXConstraint[T]] struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ExternalReportStateUpdatingBatchesCall[T, Constraint]) Return() *ExternalReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ExternalReportStateUpdatingBatchesCall[T, Constraint]) Do(f func([]string)) *ExternalReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ExternalReportStateUpdatingBatchesCall[T, Constraint]) DoAndReturn(f func([]string)) *ExternalReportStateUpdatingBatchesCall[T, Constraint] {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockServiceInbound is a mock of ServiceInbound interface.
type MockServiceInbound struct {
	ctrl     *gomock.Controller
	recorder *MockServiceInboundMockRecorder
}

// MockServiceInboundMockRecorder is the mock recorder for MockServiceInbound.
type MockServiceInboundMockRecorder struct {
	mock *MockServiceInbound
}

// NewMockServiceInbound creates a new mock instance.
func NewMockServiceInbound(ctrl *gomock.Controller) *MockServiceInbound {
	mock := &MockServiceInbound{ctrl: ctrl}
	mock.recorder = &MockServiceInboundMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServiceInbound) EXPECT() *MockServiceInboundMockRecorder {
	return m.recorder
}

// ReportExecuted mocks base method.
func (m *MockServiceInbound) ReportExecuted(state *types.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportExecuted", state)
}

// ReportExecuted indicates an expected call of ReportExecuted.
func (mr *MockServiceInboundMockRecorder) ReportExecuted(state any) *ServiceInboundReportExecutedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockServiceInbound)(nil).ReportExecuted), state)
	return &ServiceInboundReportExecutedCall{Call: call}
}

// ServiceInboundReportExecutedCall wrap *gomock.Call
type ServiceInboundReportExecutedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ServiceInboundReportExecutedCall) Return() *ServiceInboundReportExecutedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ServiceInboundReportExecutedCall) Do(f func(*types.ServiceState)) *ServiceInboundReportExecutedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ServiceInboundReportExecutedCall) DoAndReturn(f func(*types.ServiceState)) *ServiceInboundReportExecutedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReportStateUpdated mocks base method.
func (m *MockServiceInbound) ReportStateUpdated(state *types.ServiceSyncState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated.
func (mr *MockServiceInboundMockRecorder) ReportStateUpdated(state any) *ServiceInboundReportStateUpdatedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockServiceInbound)(nil).ReportStateUpdated), state)
	return &ServiceInboundReportStateUpdatedCall{Call: call}
}

// ServiceInboundReportStateUpdatedCall wrap *gomock.Call
type ServiceInboundReportStateUpdatedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ServiceInboundReportStateUpdatedCall) Return() *ServiceInboundReportStateUpdatedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ServiceInboundReportStateUpdatedCall) Do(f func(*types.ServiceSyncState)) *ServiceInboundReportStateUpdatedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ServiceInboundReportStateUpdatedCall) DoAndReturn(f func(*types.ServiceSyncState)) *ServiceInboundReportStateUpdatedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
