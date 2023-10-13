package txpool

import (
	"go.uber.org/mock/gomock"

	"github.com/axiomesh/axiom-bft/common/consensus"
)

// NewMockMinimalTxPool returns a minimal implement of MockTxPool which accepts
// any kinds of input and returns 'zero value' as all outputs.
// Users can defines custom MockTxPool like this:
// func NewMockCustomTxPool(ctrl *gomock.Controller) *MockTxPool {...}
// in which users must specify output for all functions.
func NewMockMinimalTxPool[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockTxPool[T, Constraint] {
	mock := NewMockTxPool[T, Constraint](ctrl)
	mock.EXPECT().GenerateRequestBatch().Return(nil).AnyTimes()
	mock.EXPECT().AddNewRequests(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().RemoveBatches(gomock.Any()).Return().AnyTimes()
	mock.EXPECT().IsPoolFull().Return(false).AnyTimes()
	mock.EXPECT().HasPendingRequestInPool().Return(false).AnyTimes()
	mock.EXPECT().RestoreOneBatch(gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().GetRequestsByHashList(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil, nil, nil).AnyTimes()
	mock.EXPECT().SendMissingRequests(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().ReceiveMissingRequests(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().FilterOutOfDateRequests().Return(nil, nil).AnyTimes()
	mock.EXPECT().RestorePool().Return().AnyTimes()
	mock.EXPECT().ReConstructBatchByOrder(gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().Reset(gomock.Any()).Return().AnyTimes()
	mock.EXPECT().Stop().AnyTimes()
	mock.EXPECT().Start().Return(nil).AnyTimes()
	mock.EXPECT().Init(gomock.Any()).AnyTimes()
	return mock
}