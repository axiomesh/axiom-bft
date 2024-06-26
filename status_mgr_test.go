package rbft

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/axiomesh/axiom-bft/common"
	"github.com/axiomesh/axiom-bft/common/consensus"
	"github.com/axiomesh/axiom-bft/common/metrics/disabled"
	"github.com/axiomesh/axiom-bft/types"
	"github.com/axiomesh/axiom-kit/txpool/mock_txpool"
	kittypes "github.com/axiomesh/axiom-kit/types"
)

func newTestStatusNode[T any, Constraint kittypes.TXConstraint[T]](ctrl *gomock.Controller) *rbftImpl[T, Constraint] {
	log := common.NewSimpleLogger()
	external := NewMockMinimalExternal[T, Constraint](ctrl)
	conf := Config{
		LastServiceState: &types.ServiceState{
			MetaState: &types.MetaState{},
			Epoch:     1,
		},
		SelfP2PNodeID: "node1",
		GenesisEpochInfo: &kittypes.EpochInfo{
			Epoch:       1,
			EpochPeriod: 1000,
			StartBlock:  1,
			ConsensusParams: kittypes.ConsensusParams{
				ProposerElectionType:          ProposerElectionTypeAbnormalRotation,
				CheckpointPeriod:              10,
				HighWatermarkCheckpointPeriod: 4,
				MaxValidatorNum:               10,
				BlockMaxTxNum:                 500,
				NotActiveWeight:               1,
				AbnormalNodeExcludeView:       10,
				AgainProposeIntervalBlockInValidatorsNumPercentage: 30,
			},
		},
		Logger:      log,
		MetricsProv: &disabled.Provider{},
		DelFlag:     make(chan bool),
	}

	external.EXPECT().GetEpochInfo(gomock.Any()).DoAndReturn(func(u uint64) (*kittypes.EpochInfo, error) {
		return conf.GenesisEpochInfo, nil
	}).AnyTimes()

	pool := mock_txpool.NewMockMinimalTxPool[T, Constraint](4, ctrl)

	rbft, err := newRBFT[T, Constraint](conf, external, pool, true)
	if err != nil {
		panic(err)
	}
	err = rbft.init()
	if err != nil {
		panic(err)
	}
	return rbft
}

func TestStatusMgr_inOne(t *testing.T) {
	ctrl := gomock.NewController(t)
	// defer ctrl.Finish()

	rbft := newTestStatusNode[consensus.FltTransaction, *consensus.FltTransaction](ctrl)

	rbft.status.reset()
	rbft.atomicOn(Normal)
	rbft.atomicOn(InRecovery)
	assert.Equal(t, true, rbft.atomicInOne(Normal, Pending))
}

func TestStatusMgr_setState(t *testing.T) {
	ctrl := gomock.NewController(t)
	// defer ctrl.Finish()

	rbft := newTestStatusNode[consensus.FltTransaction, *consensus.FltTransaction](ctrl)

	rbft.setNormal()
	assert.Equal(t, true, rbft.in(Normal))
}

func TestStatusMgr_maybeSetNormal(t *testing.T) {
	ctrl := gomock.NewController(t)
	// defer ctrl.Finish()

	rbft := newTestStatusNode[consensus.FltTransaction, *consensus.FltTransaction](ctrl)

	rbft.atomicOff(InRecovery)
	rbft.atomicOff(InConfChange)
	rbft.atomicOff(InViewChange)
	rbft.atomicOff(StateTransferring)
	rbft.atomicOff(Pending)
	rbft.maybeSetNormal()
	assert.Equal(t, true, rbft.in(Normal))

	rbft.atomicOn(InRecovery)
	rbft.maybeSetNormal()
	assert.Equal(t, true, rbft.in(Normal))
}
