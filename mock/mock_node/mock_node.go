// Code generated by MockGen. DO NOT EDIT.
// Source: ../node.go

// Package mocknode is a generated GoMock package.
package mocknode

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	rbft "github.com/hyperchain/go-hpc-rbft"
	"github.com/hyperchain/go-hpc-rbft/common/consensus"
	types "github.com/hyperchain/go-hpc-rbft/types"
)

// MockNode is a mock of Node interface.
type MockNode struct {
	ctrl     *gomock.Controller
	recorder *MockNodeMockRecorder
}

// MockNodeMockRecorder is the mock recorder for MockNode.
type MockNodeMockRecorder struct {
	mock *MockNode
}

// NewMockNode creates a new mock instance.
func NewMockNode(ctrl *gomock.Controller) *MockNode {
	mock := &MockNode{ctrl: ctrl}
	mock.recorder = &MockNodeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNode) EXPECT() *MockNodeMockRecorder {
	return m.recorder
}

// ApplyConfChange mocks base method.
func (m *MockNode) ApplyConfChange(cc *types.ConfState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ApplyConfChange", cc)
}

// ApplyConfChange indicates an expected call of ApplyConfChange.
func (mr *MockNodeMockRecorder) ApplyConfChange(cc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplyConfChange", reflect.TypeOf((*MockNode)(nil).ApplyConfChange), cc)
}

// GetUncommittedTransactions mocks base method.
func (m *MockNode) GetUncommittedTransactions(maxsize uint64) [][]byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUncommittedTransactions", maxsize)
	ret0, _ := ret[0].([][]byte)
	return ret0
}

// GetUncommittedTransactions indicates an expected call of GetUncommittedTransactions.
func (mr *MockNodeMockRecorder) GetUncommittedTransactions(maxsize interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUncommittedTransactions", reflect.TypeOf((*MockNode)(nil).GetUncommittedTransactions), maxsize)
}

// Propose mocks base method.
func (m *MockNode) Propose(requests *consensus.RequestSet) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Propose", requests)
	ret0, _ := ret[0].(error)
	return ret0
}

// Propose indicates an expected call of Propose.
func (mr *MockNodeMockRecorder) Propose(requests interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Propose", reflect.TypeOf((*MockNode)(nil).Propose), requests)
}

// ReportExecuted mocks base method.
func (m *MockNode) ReportExecuted(state *types.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportExecuted", state)
}

// ReportExecuted indicates an expected call of ReportExecuted.
func (mr *MockNodeMockRecorder) ReportExecuted(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockNode)(nil).ReportExecuted), state)
}

// ReportStableCheckpointFinished mocks base method.
func (m *MockNode) ReportStableCheckpointFinished(height uint64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStableCheckpointFinished", height)
}

// ReportStableCheckpointFinished indicates an expected call of ReportStableCheckpointFinished.
func (mr *MockNodeMockRecorder) ReportStableCheckpointFinished(height interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStableCheckpointFinished", reflect.TypeOf((*MockNode)(nil).ReportStableCheckpointFinished), height)
}

// ReportStateUpdated mocks base method.
func (m *MockNode) ReportStateUpdated(state *types.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated.
func (mr *MockNodeMockRecorder) ReportStateUpdated(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockNode)(nil).ReportStateUpdated), state)
}

// Start mocks base method.
func (m *MockNode) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockNodeMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockNode)(nil).Start))
}

// Status mocks base method.
func (m *MockNode) Status() rbft.NodeStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(rbft.NodeStatus)
	return ret0
}

// Status indicates an expected call of Status.
func (mr *MockNodeMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockNode)(nil).Status))
}

// Step mocks base method.
func (m *MockNode) Step(ctx context.Context, msg *consensus.ConsensusMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Step", ctx, msg)
}

// Step indicates an expected call of Step.
func (mr *MockNodeMockRecorder) Step(ctx, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Step", reflect.TypeOf((*MockNode)(nil).Step), ctx, msg)
}

// Stop mocks base method.
func (m *MockNode) Stop() [][]byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].([][]byte)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockNodeMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockNode)(nil).Stop))
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
func (mr *MockServiceInboundMockRecorder) ReportExecuted(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockServiceInbound)(nil).ReportExecuted), state)
}

// ReportStableCheckpointFinished mocks base method.
func (m *MockServiceInbound) ReportStableCheckpointFinished(height uint64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStableCheckpointFinished", height)
}

// ReportStableCheckpointFinished indicates an expected call of ReportStableCheckpointFinished.
func (mr *MockServiceInboundMockRecorder) ReportStableCheckpointFinished(height interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStableCheckpointFinished", reflect.TypeOf((*MockServiceInbound)(nil).ReportStableCheckpointFinished), height)
}

// ReportStateUpdated mocks base method.
func (m *MockServiceInbound) ReportStateUpdated(state *types.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated.
func (mr *MockServiceInboundMockRecorder) ReportStateUpdated(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockServiceInbound)(nil).ReportStateUpdated), state)
}
