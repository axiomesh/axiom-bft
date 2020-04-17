// Code generated by MockGen. DO NOT EDIT.
// Source: node.go

// Package mocknode is a generated GoMock package.
package mocknode

import (
	gomock "github.com/golang/mock/gomock"
	protos "github.com/ultramesh/flato-event/inner/protos"
	flato_rbft "github.com/ultramesh/flato-rbft"
	rbftpb "github.com/ultramesh/flato-rbft/rbftpb"
	reflect "reflect"
)

// MockNode is a mock of Node interface
type MockNode struct {
	ctrl     *gomock.Controller
	recorder *MockNodeMockRecorder
}

// MockNodeMockRecorder is the mock recorder for MockNode
type MockNodeMockRecorder struct {
	mock *MockNode
}

// NewMockNode creates a new mock instance
func NewMockNode(ctrl *gomock.Controller) *MockNode {
	mock := &MockNode{ctrl: ctrl}
	mock.recorder = &MockNodeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNode) EXPECT() *MockNodeMockRecorder {
	return m.recorder
}

// Start mocks base method
func (m *MockNode) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start
func (mr *MockNodeMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockNode)(nil).Start))
}

// Propose mocks base method
func (m *MockNode) Propose(requests []*protos.Transaction) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Propose", requests)
	ret0, _ := ret[0].(error)
	return ret0
}

// Propose indicates an expected call of Propose
func (mr *MockNodeMockRecorder) Propose(requests interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Propose", reflect.TypeOf((*MockNode)(nil).Propose), requests)
}

// ProposeConfChange mocks base method
func (m *MockNode) ProposeConfChange(cc *rbftpb.ConfChange) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProposeConfChange", cc)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProposeConfChange indicates an expected call of ProposeConfChange
func (mr *MockNodeMockRecorder) ProposeConfChange(cc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProposeConfChange", reflect.TypeOf((*MockNode)(nil).ProposeConfChange), cc)
}

// Step mocks base method
func (m *MockNode) Step(msg *rbftpb.ConsensusMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Step", msg)
}

// Step indicates an expected call of Step
func (mr *MockNodeMockRecorder) Step(msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Step", reflect.TypeOf((*MockNode)(nil).Step), msg)
}

// ApplyConfChange mocks base method
func (m *MockNode) ApplyConfChange(cc *rbftpb.ConfState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ApplyConfChange", cc)
}

// ApplyConfChange indicates an expected call of ApplyConfChange
func (mr *MockNodeMockRecorder) ApplyConfChange(cc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplyConfChange", reflect.TypeOf((*MockNode)(nil).ApplyConfChange), cc)
}

// Status mocks base method
func (m *MockNode) Status() flato_rbft.NodeStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(flato_rbft.NodeStatus)
	return ret0
}

// Status indicates an expected call of Status
func (mr *MockNodeMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockNode)(nil).Status))
}

// ReportExecuted mocks base method
func (m *MockNode) ReportExecuted(state *rbftpb.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportExecuted", state)
}

// ReportExecuted indicates an expected call of ReportExecuted
func (mr *MockNodeMockRecorder) ReportExecuted(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockNode)(nil).ReportExecuted), state)
}

// ReportStateUpdated mocks base method
func (m *MockNode) ReportStateUpdated(state *rbftpb.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated
func (mr *MockNodeMockRecorder) ReportStateUpdated(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockNode)(nil).ReportStateUpdated), state)
}

// ReportRouterUpdated mocks base method
func (m *MockNode) ReportRouterUpdated(router *rbftpb.Router) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportRouterUpdated", router)
}

// ReportRouterUpdated indicates an expected call of ReportRouterUpdated
func (mr *MockNodeMockRecorder) ReportRouterUpdated(router interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportRouterUpdated", reflect.TypeOf((*MockNode)(nil).ReportRouterUpdated), router)
}

// Stop mocks base method
func (m *MockNode) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop
func (mr *MockNodeMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockNode)(nil).Stop))
}

// MockServiceInbound is a mock of ServiceInbound interface
type MockServiceInbound struct {
	ctrl     *gomock.Controller
	recorder *MockServiceInboundMockRecorder
}

// MockServiceInboundMockRecorder is the mock recorder for MockServiceInbound
type MockServiceInboundMockRecorder struct {
	mock *MockServiceInbound
}

// NewMockServiceInbound creates a new mock instance
func NewMockServiceInbound(ctrl *gomock.Controller) *MockServiceInbound {
	mock := &MockServiceInbound{ctrl: ctrl}
	mock.recorder = &MockServiceInboundMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockServiceInbound) EXPECT() *MockServiceInboundMockRecorder {
	return m.recorder
}

// ReportExecuted mocks base method
func (m *MockServiceInbound) ReportExecuted(state *rbftpb.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportExecuted", state)
}

// ReportExecuted indicates an expected call of ReportExecuted
func (mr *MockServiceInboundMockRecorder) ReportExecuted(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportExecuted", reflect.TypeOf((*MockServiceInbound)(nil).ReportExecuted), state)
}

// ReportStateUpdated mocks base method
func (m *MockServiceInbound) ReportStateUpdated(state *rbftpb.ServiceState) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportStateUpdated", state)
}

// ReportStateUpdated indicates an expected call of ReportStateUpdated
func (mr *MockServiceInboundMockRecorder) ReportStateUpdated(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportStateUpdated", reflect.TypeOf((*MockServiceInbound)(nil).ReportStateUpdated), state)
}

// ReportRouterUpdated mocks base method
func (m *MockServiceInbound) ReportRouterUpdated(router *rbftpb.Router) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportRouterUpdated", router)
}

// ReportRouterUpdated indicates an expected call of ReportRouterUpdated
func (mr *MockServiceInboundMockRecorder) ReportRouterUpdated(router interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportRouterUpdated", reflect.TypeOf((*MockServiceInbound)(nil).ReportRouterUpdated), router)
}
