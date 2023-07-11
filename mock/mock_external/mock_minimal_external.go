package mockexternal

import (
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/hyperchain/go-hpc-rbft/v2/common/consensus"
)

// NewMockMinimalExternal returns a minimal implement of MockExternalStack which accepts
// any kinds of input and returns 'zero value' as all outputs.
// Users can defines custom MockExternalStack like this:
// func NewMockCustomMockExternalStack(ctrl *gomock.Controller) *MockExternalStack {...}
// in which users must specify output for all functions.
func NewMockMinimalExternal[T any, Constraint consensus.TXConstraint[T]](ctrl *gomock.Controller) *MockExternalStack[T, Constraint] {
	mock := NewMockExternalStack[T, Constraint](ctrl)
	mock.EXPECT().StoreState(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().DelState(gomock.Any()).Return(nil).AnyTimes()

	mock.EXPECT().ReadState(gomock.Any()).Return(nil, errors.New("ReadState Error")).AnyTimes()
	mock.EXPECT().ReadStateSet(gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().Destroy(gomock.Any()).Return(nil).AnyTimes()

	mock.EXPECT().Broadcast(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().Unicast(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().UnicastByHostname(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	mock.EXPECT().Sign(gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	mock.EXPECT().Execute(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return().AnyTimes()
	mock.EXPECT().StateUpdate(gomock.Any(), gomock.Any(), gomock.Any()).Return().AnyTimes()
	mock.EXPECT().SendFilterEvent(gomock.Any(), gomock.Any()).Return().AnyTimes()

	mock.EXPECT().Reconfiguration().Return(uint64(0)).AnyTimes()
	mock.EXPECT().GetNodeInfos().Return(nil).AnyTimes()

	mock.EXPECT().IsConfigBlock(gomock.Any()).Return(false).AnyTimes()
	mock.EXPECT().GetLastCheckpoint().Return(nil).AnyTimes()
	// TODO(DH): return meaningful value.
	mock.EXPECT().GetCheckpointOfEpoch(gomock.Any()).Return(nil, nil).AnyTimes()
	mock.EXPECT().VerifyEpochChangeProof(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return mock
}
