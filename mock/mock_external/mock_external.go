// Code generated by MockGen. DO NOT EDIT.
// Source: ../external/external.go

// Package mockexternal is a generated GoMock package.
package mockexternal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	"github.com/axiomesh/axiom-bft/common/consensus"
	types "github.com/axiomesh/axiom-bft/types"
)

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// DelState mocks base method.
func (m *MockStorage) DelState(key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DelState", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// DelState indicates an expected call of DelState.
func (mr *MockStorageMockRecorder) DelState(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelState", reflect.TypeOf((*MockStorage)(nil).DelState), key)
}

// Destroy mocks base method.
func (m *MockStorage) Destroy(key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Destroy", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// Destroy indicates an expected call of Destroy.
func (mr *MockStorageMockRecorder) Destroy(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Destroy", reflect.TypeOf((*MockStorage)(nil).Destroy), key)
}

// ReadState mocks base method.
func (m *MockStorage) ReadState(key string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadState", key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadState indicates an expected call of ReadState.
func (mr *MockStorageMockRecorder) ReadState(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadState", reflect.TypeOf((*MockStorage)(nil).ReadState), key)
}

// ReadStateSet mocks base method.
func (m *MockStorage) ReadStateSet(key string) (map[string][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadStateSet", key)
	ret0, _ := ret[0].(map[string][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadStateSet indicates an expected call of ReadStateSet.
func (mr *MockStorageMockRecorder) ReadStateSet(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadStateSet", reflect.TypeOf((*MockStorage)(nil).ReadStateSet), key)
}

// StoreState mocks base method.
func (m *MockStorage) StoreState(key string, value []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreState", key, value)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreState indicates an expected call of StoreState.
func (mr *MockStorageMockRecorder) StoreState(key, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreState", reflect.TypeOf((*MockStorage)(nil).StoreState), key, value)
}

// MockNetwork is a mock of Network interface.
type MockNetwork struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkMockRecorder
}

// MockNetworkMockRecorder is the mock recorder for MockNetwork.
type MockNetworkMockRecorder struct {
	mock *MockNetwork
}

// NewMockNetwork creates a new mock instance.
func NewMockNetwork(ctrl *gomock.Controller) *MockNetwork {
	mock := &MockNetwork{ctrl: ctrl}
	mock.recorder = &MockNetworkMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork) EXPECT() *MockNetworkMockRecorder {
	return m.recorder
}

// Broadcast mocks base method.
func (m *MockNetwork) Broadcast(ctx context.Context, msg *consensus.ConsensusMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Broadcast", ctx, msg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Broadcast indicates an expected call of Broadcast.
func (mr *MockNetworkMockRecorder) Broadcast(ctx, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Broadcast", reflect.TypeOf((*MockNetwork)(nil).Broadcast), ctx, msg)
}

// Unicast mocks base method.
func (m *MockNetwork) Unicast(ctx context.Context, msg *consensus.ConsensusMessage, to uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unicast", ctx, msg, to)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unicast indicates an expected call of Unicast.
func (mr *MockNetworkMockRecorder) Unicast(ctx, msg, to interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unicast", reflect.TypeOf((*MockNetwork)(nil).Unicast), ctx, msg, to)
}

// UnicastByHostname mocks base method.
func (m *MockNetwork) UnicastByHostname(ctx context.Context, msg *consensus.ConsensusMessage, to string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnicastByHostname", ctx, msg, to)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnicastByHostname indicates an expected call of UnicastByHostname.
func (mr *MockNetworkMockRecorder) UnicastByHostname(ctx, msg, to interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnicastByHostname", reflect.TypeOf((*MockNetwork)(nil).UnicastByHostname), ctx, msg, to)
}

// MockCrypto is a mock of Crypto interface.
type MockCrypto struct {
	ctrl     *gomock.Controller
	recorder *MockCryptoMockRecorder
}

// MockCryptoMockRecorder is the mock recorder for MockCrypto.
type MockCryptoMockRecorder struct {
	mock *MockCrypto
}

// NewMockCrypto creates a new mock instance.
func NewMockCrypto(ctrl *gomock.Controller) *MockCrypto {
	mock := &MockCrypto{ctrl: ctrl}
	mock.recorder = &MockCryptoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCrypto) EXPECT() *MockCryptoMockRecorder {
	return m.recorder
}

// Sign mocks base method.
func (m *MockCrypto) Sign(msg []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", msg)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockCryptoMockRecorder) Sign(msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockCrypto)(nil).Sign), msg)
}

// Verify mocks base method.
func (m *MockCrypto) Verify(peerHash string, signature, msg []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", peerHash, signature, msg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockCryptoMockRecorder) Verify(peerHash, signature, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockCrypto)(nil).Verify), peerHash, signature, msg)
}

// MockServiceOutbound is a mock of ServiceOutbound interface.
type MockServiceOutbound struct {
	ctrl     *gomock.Controller
	recorder *MockServiceOutboundMockRecorder
}

// MockServiceOutboundMockRecorder is the mock recorder for MockServiceOutbound.
type MockServiceOutboundMockRecorder struct {
	mock *MockServiceOutbound
}

// NewMockServiceOutbound creates a new mock instance.
func NewMockServiceOutbound(ctrl *gomock.Controller) *MockServiceOutbound {
	mock := &MockServiceOutbound{ctrl: ctrl}
	mock.recorder = &MockServiceOutboundMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServiceOutbound) EXPECT() *MockServiceOutboundMockRecorder {
	return m.recorder
}

// Execute mocks base method.
func (m *MockServiceOutbound) Execute(txs [][]byte, localList []bool, seqNo uint64, timestamp int64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Execute", txs, localList, seqNo, timestamp)
}

// Execute indicates an expected call of Execute.
func (mr *MockServiceOutboundMockRecorder) Execute(txs, localList, seqNo, timestamp interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Execute", reflect.TypeOf((*MockServiceOutbound)(nil).Execute), txs, localList, seqNo, timestamp)
}

// SendFilterEvent mocks base method.
func (m *MockServiceOutbound) SendFilterEvent(informType types.InformType, message ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{informType}
	for _, a := range message {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "SendFilterEvent", varargs...)
}

// SendFilterEvent indicates an expected call of SendFilterEvent.
func (mr *MockServiceOutboundMockRecorder) SendFilterEvent(informType interface{}, message ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{informType}, message...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendFilterEvent", reflect.TypeOf((*MockServiceOutbound)(nil).SendFilterEvent), varargs...)
}

// StateUpdate mocks base method.
func (m *MockServiceOutbound) StateUpdate(seqNo uint64, digest string, checkpoints []*consensus.SignedCheckpoint, epochChanges ...*consensus.QuorumCheckpoint) {
	m.ctrl.T.Helper()
	varargs := []interface{}{seqNo, digest, checkpoints}
	for _, a := range epochChanges {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "StateUpdate", varargs...)
}

// StateUpdate indicates an expected call of StateUpdate.
func (mr *MockServiceOutboundMockRecorder) StateUpdate(seqNo, digest, checkpoints interface{}, epochChanges ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{seqNo, digest, checkpoints}, epochChanges...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StateUpdate", reflect.TypeOf((*MockServiceOutbound)(nil).StateUpdate), varargs...)
}

// MockEpochService is a mock of EpochService interface.
type MockEpochService struct {
	ctrl     *gomock.Controller
	recorder *MockEpochServiceMockRecorder
}

// MockEpochServiceMockRecorder is the mock recorder for MockEpochService.
type MockEpochServiceMockRecorder struct {
	mock *MockEpochService
}

// NewMockEpochService creates a new mock instance.
func NewMockEpochService(ctrl *gomock.Controller) *MockEpochService {
	mock := &MockEpochService{ctrl: ctrl}
	mock.recorder = &MockEpochServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEpochService) EXPECT() *MockEpochServiceMockRecorder {
	return m.recorder
}

// GetAlgorithmVersion mocks base method.
func (m *MockEpochService) GetAlgorithmVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAlgorithmVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAlgorithmVersion indicates an expected call of GetAlgorithmVersion.
func (mr *MockEpochServiceMockRecorder) GetAlgorithmVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAlgorithmVersion", reflect.TypeOf((*MockEpochService)(nil).GetAlgorithmVersion))
}

// GetCheckpointOfEpoch mocks base method.
func (m *MockEpochService) GetCheckpointOfEpoch(epoch uint64) (*consensus.QuorumCheckpoint, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCheckpointOfEpoch", epoch)
	ret0, _ := ret[0].(*consensus.QuorumCheckpoint)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCheckpointOfEpoch indicates an expected call of GetCheckpointOfEpoch.
func (mr *MockEpochServiceMockRecorder) GetCheckpointOfEpoch(epoch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCheckpointOfEpoch", reflect.TypeOf((*MockEpochService)(nil).GetCheckpointOfEpoch), epoch)
}

// GetEpoch mocks base method.
func (m *MockEpochService) GetEpoch() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEpoch")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetEpoch indicates an expected call of GetEpoch.
func (mr *MockEpochServiceMockRecorder) GetEpoch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEpoch", reflect.TypeOf((*MockEpochService)(nil).GetEpoch))
}

// GetLastCheckpoint mocks base method.
func (m *MockEpochService) GetLastCheckpoint() *consensus.QuorumCheckpoint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLastCheckpoint")
	ret0, _ := ret[0].(*consensus.QuorumCheckpoint)
	return ret0
}

// GetLastCheckpoint indicates an expected call of GetLastCheckpoint.
func (mr *MockEpochServiceMockRecorder) GetLastCheckpoint() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLastCheckpoint", reflect.TypeOf((*MockEpochService)(nil).GetLastCheckpoint))
}

// GetNodeInfos mocks base method.
func (m *MockEpochService) GetNodeInfos() []*consensus.NodeInfo {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeInfos")
	ret0, _ := ret[0].([]*consensus.NodeInfo)
	return ret0
}

// GetNodeInfos indicates an expected call of GetNodeInfos.
func (mr *MockEpochServiceMockRecorder) GetNodeInfos() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeInfos", reflect.TypeOf((*MockEpochService)(nil).GetNodeInfos))
}

// IsConfigBlock mocks base method.
func (m *MockEpochService) IsConfigBlock(height uint64) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConfigBlock", height)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConfigBlock indicates an expected call of IsConfigBlock.
func (mr *MockEpochServiceMockRecorder) IsConfigBlock(height interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConfigBlock", reflect.TypeOf((*MockEpochService)(nil).IsConfigBlock), height)
}

// Reconfiguration mocks base method.
func (m *MockEpochService) Reconfiguration() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reconfiguration")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// Reconfiguration indicates an expected call of Reconfiguration.
func (mr *MockEpochServiceMockRecorder) Reconfiguration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reconfiguration", reflect.TypeOf((*MockEpochService)(nil).Reconfiguration))
}

// VerifyEpochChangeProof mocks base method.
func (m *MockEpochService) VerifyEpochChangeProof(proof *consensus.EpochChangeProof, validators consensus.Validators) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyEpochChangeProof", proof, validators)
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyEpochChangeProof indicates an expected call of VerifyEpochChangeProof.
func (mr *MockEpochServiceMockRecorder) VerifyEpochChangeProof(proof, validators interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyEpochChangeProof", reflect.TypeOf((*MockEpochService)(nil).VerifyEpochChangeProof), proof, validators)
}

// MockExternalStack is a mock of ExternalStack interface.
type MockExternalStack[T any, Constraint consensus.TXConstraint[T]] struct {
	ctrl     *gomock.Controller
	recorder *MockExternalStackMockRecorder[T, Constraint]
}

// MockExternalStackMockRecorder is the mock recorder for MockExternalStack.
type MockExternalStackMockRecorder[T any, Constraint consensus.TXConstraint[T]] struct {
	mock *MockExternalStack[T, Constraint]
}

// NewMockExternalStack creates a new mock instance.
func NewMockExternalStack[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockExternalStack[T, Constraint] {
	mock := &MockExternalStack[T, Constraint]{ctrl: ctrl}
	mock.recorder = &MockExternalStackMockRecorder[T, Constraint]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockExternalStack[T, Constraint]) EXPECT() *MockExternalStackMockRecorder[T, Constraint] {
	return m.recorder
}

// Broadcast mocks base method.
func (m *MockExternalStack[T, Constraint]) Broadcast(ctx context.Context, msg *consensus.ConsensusMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Broadcast", ctx, msg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Broadcast indicates an expected call of Broadcast.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Broadcast(ctx, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Broadcast", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Broadcast), ctx, msg)
}

// DelState mocks base method.
func (m *MockExternalStack[T, Constraint]) DelState(key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DelState", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// DelState indicates an expected call of DelState.
func (mr *MockExternalStackMockRecorder[T, Constraint]) DelState(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelState", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).DelState), key)
}

// Destroy mocks base method.
func (m *MockExternalStack[T, Constraint]) Destroy(key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Destroy", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// Destroy indicates an expected call of Destroy.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Destroy(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Destroy", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Destroy), key)
}

// Execute mocks base method.
func (m *MockExternalStack[T, Constraint]) Execute(txs [][]byte, localList []bool, seqNo uint64, timestamp int64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Execute", txs, localList, seqNo, timestamp)
}

// Execute indicates an expected call of Execute.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Execute(txs, localList, seqNo, timestamp interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Execute", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Execute), txs, localList, seqNo, timestamp)
}

// GetAlgorithmVersion mocks base method.
func (m *MockExternalStack[T, Constraint]) GetAlgorithmVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAlgorithmVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAlgorithmVersion indicates an expected call of GetAlgorithmVersion.
func (mr *MockExternalStackMockRecorder[T, Constraint]) GetAlgorithmVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAlgorithmVersion", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).GetAlgorithmVersion))
}

// GetCheckpointOfEpoch mocks base method.
func (m *MockExternalStack[T, Constraint]) GetCheckpointOfEpoch(epoch uint64) (*consensus.QuorumCheckpoint, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCheckpointOfEpoch", epoch)
	ret0, _ := ret[0].(*consensus.QuorumCheckpoint)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCheckpointOfEpoch indicates an expected call of GetCheckpointOfEpoch.
func (mr *MockExternalStackMockRecorder[T, Constraint]) GetCheckpointOfEpoch(epoch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCheckpointOfEpoch", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).GetCheckpointOfEpoch), epoch)
}

// GetEpoch mocks base method.
func (m *MockExternalStack[T, Constraint]) GetEpoch() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEpoch")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetEpoch indicates an expected call of GetEpoch.
func (mr *MockExternalStackMockRecorder[T, Constraint]) GetEpoch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEpoch", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).GetEpoch))
}

// GetLastCheckpoint mocks base method.
func (m *MockExternalStack[T, Constraint]) GetLastCheckpoint() *consensus.QuorumCheckpoint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLastCheckpoint")
	ret0, _ := ret[0].(*consensus.QuorumCheckpoint)
	return ret0
}

// GetLastCheckpoint indicates an expected call of GetLastCheckpoint.
func (mr *MockExternalStackMockRecorder[T, Constraint]) GetLastCheckpoint() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLastCheckpoint", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).GetLastCheckpoint))
}

// GetNodeInfos mocks base method.
func (m *MockExternalStack[T, Constraint]) GetNodeInfos() []*consensus.NodeInfo {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeInfos")
	ret0, _ := ret[0].([]*consensus.NodeInfo)
	return ret0
}

// GetNodeInfos indicates an expected call of GetNodeInfos.
func (mr *MockExternalStackMockRecorder[T, Constraint]) GetNodeInfos() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeInfos", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).GetNodeInfos))
}

// IsConfigBlock mocks base method.
func (m *MockExternalStack[T, Constraint]) IsConfigBlock(height uint64) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConfigBlock", height)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConfigBlock indicates an expected call of IsConfigBlock.
func (mr *MockExternalStackMockRecorder[T, Constraint]) IsConfigBlock(height interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConfigBlock", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).IsConfigBlock), height)
}

// ReadState mocks base method.
func (m *MockExternalStack[T, Constraint]) ReadState(key string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadState", key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadState indicates an expected call of ReadState.
func (mr *MockExternalStackMockRecorder[T, Constraint]) ReadState(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadState", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).ReadState), key)
}

// ReadStateSet mocks base method.
func (m *MockExternalStack[T, Constraint]) ReadStateSet(key string) (map[string][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadStateSet", key)
	ret0, _ := ret[0].(map[string][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadStateSet indicates an expected call of ReadStateSet.
func (mr *MockExternalStackMockRecorder[T, Constraint]) ReadStateSet(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadStateSet", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).ReadStateSet), key)
}

// Reconfiguration mocks base method.
func (m *MockExternalStack[T, Constraint]) Reconfiguration() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reconfiguration")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// Reconfiguration indicates an expected call of Reconfiguration.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Reconfiguration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reconfiguration", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Reconfiguration))
}

// SendFilterEvent mocks base method.
func (m *MockExternalStack[T, Constraint]) SendFilterEvent(informType types.InformType, message ...interface{}) {
	m.ctrl.T.Helper()
	varargs := []interface{}{informType}
	for _, a := range message {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "SendFilterEvent", varargs...)
}

// SendFilterEvent indicates an expected call of SendFilterEvent.
func (mr *MockExternalStackMockRecorder[T, Constraint]) SendFilterEvent(informType interface{}, message ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{informType}, message...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendFilterEvent", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).SendFilterEvent), varargs...)
}

// Sign mocks base method.
func (m *MockExternalStack[T, Constraint]) Sign(msg []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", msg)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Sign(msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Sign), msg)
}

// StateUpdate mocks base method.
func (m *MockExternalStack[T, Constraint]) StateUpdate(seqNo uint64, digest string, checkpoints []*consensus.SignedCheckpoint, epochChanges ...*consensus.QuorumCheckpoint) {
	m.ctrl.T.Helper()
	varargs := []interface{}{seqNo, digest, checkpoints}
	for _, a := range epochChanges {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "StateUpdate", varargs...)
}

// StateUpdate indicates an expected call of StateUpdate.
func (mr *MockExternalStackMockRecorder[T, Constraint]) StateUpdate(seqNo, digest, checkpoints interface{}, epochChanges ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{seqNo, digest, checkpoints}, epochChanges...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StateUpdate", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).StateUpdate), varargs...)
}

// StoreState mocks base method.
func (m *MockExternalStack[T, Constraint]) StoreState(key string, value []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreState", key, value)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreState indicates an expected call of StoreState.
func (mr *MockExternalStackMockRecorder[T, Constraint]) StoreState(key, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreState", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).StoreState), key, value)
}

// Unicast mocks base method.
func (m *MockExternalStack[T, Constraint]) Unicast(ctx context.Context, msg *consensus.ConsensusMessage, to uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unicast", ctx, msg, to)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unicast indicates an expected call of Unicast.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Unicast(ctx, msg, to interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unicast", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Unicast), ctx, msg, to)
}

// UnicastByHostname mocks base method.
func (m *MockExternalStack[T, Constraint]) UnicastByHostname(ctx context.Context, msg *consensus.ConsensusMessage, to string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnicastByHostname", ctx, msg, to)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnicastByHostname indicates an expected call of UnicastByHostname.
func (mr *MockExternalStackMockRecorder[T, Constraint]) UnicastByHostname(ctx, msg, to interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnicastByHostname", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).UnicastByHostname), ctx, msg, to)
}

// Verify mocks base method.
func (m *MockExternalStack[T, Constraint]) Verify(peerHash string, signature, msg []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", peerHash, signature, msg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockExternalStackMockRecorder[T, Constraint]) Verify(peerHash, signature, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).Verify), peerHash, signature, msg)
}

// VerifyEpochChangeProof mocks base method.
func (m *MockExternalStack[T, Constraint]) VerifyEpochChangeProof(proof *consensus.EpochChangeProof, validators consensus.Validators) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyEpochChangeProof", proof, validators)
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyEpochChangeProof indicates an expected call of VerifyEpochChangeProof.
func (mr *MockExternalStackMockRecorder[T, Constraint]) VerifyEpochChangeProof(proof, validators interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyEpochChangeProof", reflect.TypeOf((*MockExternalStack[T, Constraint])(nil).VerifyEpochChangeProof), proof, validators)
}
