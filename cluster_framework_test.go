package rbft

import (
	"errors"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ultramesh/fancylogger"
	"github.com/ultramesh/flato-event/inner/protos"
	"github.com/ultramesh/flato-rbft/external"
	pb "github.com/ultramesh/flato-rbft/rbftpb"
	"github.com/ultramesh/flato-txpool"

	"github.com/gogo/protobuf/proto"
)

// testFramework contains the core structure of test framework instance.
type testFramework struct {
	N     int
	f     int
	NLock sync.RWMutex

	// Instance of nodes.
	TestNode []*testNode

	// testFramework.Peers is the router map in cluster.
	// we could regard it as the routerInfo of epoch in trusted node
	Router pb.Router

	Epoch uint64

	Digest  string
	Applied uint64
	blocks  map[uint64]string
	vset    map[uint64]pb.Router

	// Channel to close this event process.
	close chan bool

	// Channel to receive messages sent from nodes in cluster.
	clusterChan chan *channelMsg

	// Write logger to record some info.
	log Logger
}

// testNode contains the parameters of one node instance.
type testNode struct {
	// Node is provided for application to contact wih RBFT core.
	N Node

	// n is provided for testers to check RBFT core info.
	// Generally not used.
	n *node

	// testNode.Peers is the router map in one node.
	Router pb.Router

	// some important states for consensus
	Epoch   uint64
	Digest  string
	Applied uint64

	// blocks created
	blocks map[uint64]string

	// vSet values which will be stored in blocks
	vset map[uint64]pb.Router

	// ID is the num-identity of the local rbft.peerPool.localIDde.
	ID       uint64
	Hostname string

	// Normal indicates if current node could deal with messages.
	normal bool

	// Online indicates if current node could receive or send messages.
	online bool

	// Channel to close this event process.
	close chan bool

	// Channel to receive messages in cluster.
	recvChan chan *pb.ConsensusMessage

	// Storage of consensus logs.
	stateStore map[string][]byte
}

// testExternal is the instance of External interface.
type testExternal struct {
	tf *testFramework

	// testNode indicates which node the Service belongs to.
	testNode *testNode

	// Channel to receive messages sent from nodes in cluster.
	clusterChan chan *channelMsg
}

// channelMsg is the form of data in cluster network.
type channelMsg struct {
	// Target of consensus message.
	// When it is 0, the channelMsg is a broadcast message.
	// Or it means a unicast's target.
	to string

	// consensus message
	msg *pb.ConsensusMessage
}

// defaultRequestLookupSmokeTest
type defaultRequestLookupSmokeTest struct{}

func (lookup *defaultRequestLookupSmokeTest) IsRequestExist(tx *protos.Transaction) bool {
	return false
}

// NewRawLoggerFile create log file for local cluster tests
func FrameworkNewRawLoggerFile(hostname string) *fancylogger.Logger {
	rawLogger := fancylogger.NewLogger("test", fancylogger.DEBUG)

	consoleFormatter := &fancylogger.StringFormatter{
		EnableColors:    true,
		TimestampFormat: "2006-01-02T15:04:05.000",
		IsTerminal:      true,
	}

	//test with logger files
	_ = os.Mkdir("testLogger", os.ModePerm)
	fileName := "testLogger/" + hostname + ".log"
	f, _ := os.Create(fileName)
	consoleBackend := fancylogger.NewIOBackend(consoleFormatter, f)

	rawLogger.SetBackends(consoleBackend)
	rawLogger.SetEnableCaller(true)

	return rawLogger
}

// NewRawLoggerFile create log file for local cluster tests
func FrameworkNewRawLogger() *fancylogger.Logger {
	rawLogger := fancylogger.NewLogger("test", fancylogger.DEBUG)

	consoleFormatter := &fancylogger.StringFormatter{
		EnableColors:    true,
		TimestampFormat: "2006-01-02T15:04:05.000",
		IsTerminal:      true,
	}

	consoleBackend := fancylogger.NewIOBackend(consoleFormatter, os.Stdout)

	rawLogger.SetBackends(consoleBackend)
	rawLogger.SetEnableCaller(true)

	return rawLogger
}

//=============================================================================
// init process
//=============================================================================
// newTestFramework init the testFramework instance
func newTestFramework(account int, loggerFile bool) *testFramework {
	// Init PeerSet
	router := &pb.Router{}
	for i := 0; i < account; i++ {
		id := uint64(i + 1)
		hostname := "node" + strconv.Itoa(i+1)
		peer := &pb.Peer{
			Id:       id,
			Hash:     hash(hostname),
			Hostname: hostname,
		}
		router.Peers = append(router.Peers, peer)
	}

	cc := make(chan *channelMsg, 1)
	// Init Framework
	tf := &testFramework{
		TestNode: nil,
		Router:   getRouter(router),

		close:       make(chan bool),
		clusterChan: cc,

		blocks: make(map[uint64]string),
		vset:   make(map[uint64]pb.Router),

		log: NewRawLogger(),
	}

	tf.log.Debugf("%s", tf.Router)

	// set node number
	tf.setN(len(tf.Router.Peers))

	// Init testNode in TestFramework
	for i := range tf.Router.Peers {
		tn := tf.newTestNode(tf.Router.Peers[i].Id, tf.Router.Peers[i].Hostname, cc, loggerFile)
		tf.TestNode = append(tf.TestNode, tn)
	}

	return tf
}

// newNodeConfig init the Config of Node.
func (tf *testFramework) newNodeConfig(id uint64, hostname string, isNew bool, log Logger, ext external.ExternalStack, pool txpool.TxPool) Config {
	return Config{
		ID:                      id,
		Hash:                    hash(hostname),
		Hostname:                hostname,
		IsNew:                   isNew,
		Peers:                   tf.Router.Peers,
		K:                       10,
		LogMultiplier:           4,
		SetSize:                 25,
		SetTimeout:              100 * time.Millisecond,
		BatchTimeout:            500 * time.Millisecond,
		RequestTimeout:          6 * time.Second,
		NullRequestTimeout:      9 * time.Second,
		VcResendTimeout:         10 * time.Second,
		CleanVCTimeout:          60 * time.Second,
		NewViewTimeout:          8 * time.Second,
		FirstRequestTimeout:     30 * time.Second,
		SyncStateTimeout:        1 * time.Second,
		SyncStateRestartTimeout: 10 * time.Second,
		RecoveryTimeout:         10 * time.Second,
		EpochCheckTimeout:       4 * time.Second,
		CheckPoolTimeout:        3 * time.Minute,
		RequestSethMemLimit:     true,
		RequestSetMaxMem:        DefaultRequestSetMaxMem,

		Logger:      log,
		External:    ext,
		RequestPool: pool,

		EpochInit:       uint64(0),
		EpochInitDigest: "XXX GENESIS",
	}
}

func getRouter(router *pb.Router) pb.Router {
	var r pb.Router
	for _, p := range router.Peers {
		peer := pb.Peer{
			Id:       p.Id,
			Hash:     p.Hash,
			Hostname: p.Hostname,
		}
		r.Peers = append(r.Peers, &peer)
	}
	return r
}

// newTestNode init the testNode instance
func (tf *testFramework) newTestNode(id uint64, hostname string, cc chan *channelMsg, loggerFile bool) *testNode {
	// Init logger
	var log *fancylogger.Logger
	if loggerFile {
		log = FrameworkNewRawLoggerFile(hostname)
	} else {
		log = FrameworkNewRawLogger()
	}

	// Simulation Function of External
	var ext external.ExternalStack
	testExt := &testExternal{
		tf:          tf,
		testNode:    nil,
		clusterChan: cc,
	}
	ext = testExt

	// TxPool Instance, Parameters in Config are Flexible
	confTxPool := txpool.Config{
		PoolSize:      100000,
		BatchSize:     4,
		BatchMemLimit: false,
		BatchMaxMem:   999,
		ToleranceTime: 999 * time.Millisecond,
		Logger:        log,
	}
	rlu := &defaultRequestLookupSmokeTest{}
	namespace := "global"
	pool := txpool.NewTxPool(namespace, rlu, confTxPool)

	conf := tf.newNodeConfig(id, hostname, false, log, ext, pool)
	n, _ := newNode(conf)
	N := n
	tn := &testNode{
		N:          N,
		n:          n,
		Router:     getRouter(&tf.Router),
		Epoch:      n.rbft.epoch,
		ID:         id,
		Hostname:   hostname,
		normal:     true,
		online:     true,
		close:      make(chan bool),
		recvChan:   make(chan *pb.ConsensusMessage),
		stateStore: make(map[string][]byte),
		blocks:     make(map[uint64]string),
		vset:       make(map[uint64]pb.Router),
	}
	testExt.testNode = tn

	// Init State
	stateInit := &pb.ServiceState{}
	stateInit.MetaState = &pb.MetaState{
		Applied: 0,
		Digest:  "",
	}
	tn.N.ReportExecuted(stateInit)

	return tn
}

// =============================================================================
// general process method
// =============================================================================
// clusterListen listens and process the messages sent from nodes.
func (tf *testFramework) clusterListen() {
	for {
		select {
		case <-tf.close:
			return
		case obj := <-tf.clusterChan:
			for i := range tf.TestNode {
				if obj.to == "" || obj.to == tf.TestNode[i].n.rbft.peerPool.hash {
					if tf.TestNode[i].online {
						tf.TestNode[i].recvChan <- obj.msg
					}
				}
			}
		}
	}
}

// nodeListen listens and process the messages received from cluster.
func (tn *testNode) nodeListen() {
	for {
		if tn.online == false {
			tn.N.Stop()
		}

		select {
		case <-tn.close:
			return
		case msg := <-tn.recvChan:
			if tn.normal {
				tn.N.Step(msg)
			}
		}
	}
}

// frameworkStart starts the cluster of RBFT test nodes.
func (tf *testFramework) frameworkStart() {
	tf.log.Notice("Test Framework starting...")

	go tf.clusterListen()

	for i := range tf.TestNode {
		_ = tf.TestNode[i].N.Start()
		go tf.TestNode[i].nodeListen()
	}
}

// startNode starts node according to id
func (tf *testFramework) startNode(id uint64) {
	for i := range tf.TestNode {
		if uint64(i) == id {
			tf.TestNode[i].online = true
			_ = tf.TestNode[i].N.Start()
			go tf.TestNode[i].nodeListen()
		}
	}
}

// stopNode stops node according to id
func (tf *testFramework) stopNode(id uint64) {
	for i := range tf.TestNode {
		if uint64(i) == id {
			if tf.TestNode[i].close != nil {
				close(tf.TestNode[i].close)
				tf.TestNode[i].close = nil
			}

			tf.TestNode[i].online = false
			tf.TestNode[i].N.Stop()
		}
	}
}

// frameworkStop stops the cluster of RBFT test nodes.
func (tf *testFramework) frameworkStop() {
	tf.log.Notice("Test Framework stopping...")

	for i := range tf.TestNode {
		if tf.TestNode[i].close != nil {
			close(tf.TestNode[i].close)
			tf.TestNode[i].close = nil
		}
	}

	if tf.close != nil {
		close(tf.close)
		tf.close = nil
	}

	for i := range tf.TestNode {
		tf.TestNode[i].online = false
		tf.TestNode[i].N.Stop()
	}
	tf.log.Noticef("======== Every Node in Cluster stopped!")
}

// frameworkDelNode adds one node to the cluster.
func (tf *testFramework) frameworkDelNode(hostname string) {
	hash := hash(hostname)
	tf.log.Noticef("Test Framework delete Node, Hash: %s...", hostname)

	// stop node id
	for i, node := range tf.TestNode {
		if node.Hostname == hostname {
			tf.TestNode[i].online = false
			tf.TestNode[i].N.Stop()
		}
	}

	// send config change tx
	go func() {
		var (
			senderID     uint64
			senderHost   string
			senderIndex  int
			senderRouter pb.Router
		)

		senderID = uint64(2)
		delRouter := pb.Router{}
		for index, node := range tf.TestNode {
			if node.ID == senderID {
				senderHost = node.Hostname
				senderIndex = index
				senderRouter = getRouter(&node.Router)
				break
			}
		}

		delPeer := pb.Peer{
			Hash:     hash,
			Hostname: hostname,
		}

		index := uint64(0)
		for _, node := range senderRouter.Peers {
			if node.Hostname != hostname {
				index++
				node.Id = index
				delRouter.Peers = append(delRouter.Peers, node)
			} else {
				delPeer.Id = node.Id
			}
		}

		tf.log.Infof("[Cluster_Service %s] Del Node Req: %+v", senderHost, delPeer)
		tf.log.Infof("[Cluster_Service %s] Target Validator Set: %+v", senderHost, delRouter)

		info, _ := proto.Marshal(&delRouter)
		tx := &protos.Transaction{
			Timestamp: time.Now().UnixNano(),
			Id:        2,
			Nonce:     999,

			// use new router as value
			Value:  info,
			TxType: protos.Transaction_CTX,
		}
		txSet := []*protos.Transaction{tx}
		_ = tf.TestNode[senderIndex].N.Propose(txSet)
	}()
}

// frameworkAddNode adds one node to the cluster.
func (tf *testFramework) frameworkAddNode(hostname string, loggerFile bool) {
	tf.log.Noticef("Test Framework add Node, Host: %s...", hostname)

	maxID := uint64(0)
	for _, node := range tf.TestNode {
		if node.online {
			maxID++
		}
	}
	id := maxID + 1

	// Init logger
	var log *fancylogger.Logger
	if loggerFile {
		log = FrameworkNewRawLoggerFile(hostname)
	} else {
		log = FrameworkNewRawLogger()
	}

	// Simulation Function of External
	var ext external.ExternalStack
	testExt := &testExternal{
		tf:          tf,
		testNode:    nil,
		clusterChan: tf.clusterChan,
	}
	ext = testExt

	// TxPool Instance, Parameters in Config are Flexible
	confTxPool := txpool.Config{
		PoolSize:      100000,
		BatchSize:     2,
		BatchMemLimit: false,
		BatchMaxMem:   999,
		ToleranceTime: 999 * time.Millisecond,
		Logger:        log,
	}
	rlu := &defaultRequestLookupSmokeTest{}
	namespace := "global"
	pool := txpool.NewTxPool(namespace, rlu, confTxPool)

	// new peer
	hash := hash(hostname)
	newPeer := &pb.Peer{
		Id:       id,
		Hash:     hash,
		Hostname: hostname,
	}

	// Add Peer Info to Framework
	var (
		senderID     uint64
		senderHost   string
		senderIndex  int
		senderRouter pb.Router
	)
	senderID = uint64(2)

	newRouter := pb.Router{}
	for index, node := range tf.TestNode {
		if node.ID == senderID {
			senderHost = node.Hostname
			senderIndex = index
			senderRouter = getRouter(&node.Router)
			break
		}
	}
	newRouter = senderRouter
	newRouter.Peers = append(newRouter.Peers, newPeer)

	conf := tf.newNodeConfig(id, hostname, true, log, ext, pool)
	conf.Peers = newRouter.Peers
	n, _ := newNode(conf)
	N := n
	tn := &testNode{
		N:        N,
		n:        n,
		Router:   tf.Router,
		Epoch:    n.rbft.epoch,
		ID:       id,
		Hostname: hostname,
		normal:   true,
		online:   true,
		close:    make(chan bool),
		recvChan: make(chan *pb.ConsensusMessage),
		blocks:   make(map[uint64]string),
		vset:     make(map[uint64]pb.Router),
	}
	tf.TestNode = append(tf.TestNode, tn)
	testExt.testNode = tn

	// Init State
	stateInit := &pb.ServiceState{}
	stateInit.MetaState = &pb.MetaState{
		Applied: 0,
		Digest:  "",
	}
	tn.N.ReportExecuted(stateInit)

	// send config change tx
	// node4 propose a ctx to add node
	go func() {
		tf.log.Infof("[Cluster_Service %s] Add Node Req: %s", senderHost, newPeer.Hash)
		tf.log.Infof("[Cluster_Service %s] Target Validator Set: %+v", senderHost, newRouter)

		info, _ := proto.Marshal(&newRouter)
		tx := &protos.Transaction{
			Timestamp: time.Now().UnixNano(),
			Id:        2,
			Nonce:     999,

			// use new router as value
			Value:  info,
			TxType: protos.Transaction_CTX,
		}
		txSet := []*protos.Transaction{tx}
		_ = tf.TestNode[senderIndex].N.Propose(txSet)
	}()

	// Start the New Node listen, but don't start consensus
	go tn.nodeListen()
	go func() {
		_ = tn.N.Start()
	}()
}

func (tf *testFramework) sendTx(no int, sender uint64) {
	if sender == uint64(0) {
		sender = uint64(rand.Int()%tf.N + 1)
	}

	str3 := "tx" + string(no)
	tx3 := &protos.Transaction{Value: []byte(str3)}
	txs3 := []*protos.Transaction{tx3}
	_ = tf.TestNode[sender-1].N.Propose(txs3)
}

func (tf *testFramework) sendInitCtx() {
	senderID3 := uint64(rand.Int()%tf.N + 1)
	info, _ := proto.Marshal(&tf.Router)
	tx := &protos.Transaction{
		Timestamp: time.Now().UnixNano(),
		Id:        2,
		Nonce:     999,
		// use new router as value
		Value:  info,
		TxType: protos.Transaction_CTX,
	}
	txSet := []*protos.Transaction{tx}
	_ = tf.TestNode[senderID3-1].N.Propose(txSet)
}

//=============================================================================
// External Interface Implement
//=============================================================================
// Storage
func (ext *testExternal) StoreState(key string, value []byte) error {
	ext.testNode.stateStore[key] = value
	return nil
}
func (ext *testExternal) DelState(key string) error {
	delete(ext.testNode.stateStore, key)
	if ext.testNode.stateStore == nil {
		ext.testNode.stateStore = make(map[string][]byte)
	}
	return nil
}
func (ext *testExternal) ReadState(key string) ([]byte, error) {
	value := ext.testNode.stateStore[key]

	if value != nil {
		return value, nil
	}

	return nil, errors.New("empty")
}
func (ext *testExternal) ReadStateSet(key string) (map[string][]byte, error) {
	value := ext.testNode.stateStore[key]

	if value != nil {
		ret := map[string][]byte{
			key: value,
		}
		return ret, nil
	}

	return nil, errors.New("empty")
}
func (ext *testExternal) Destroy() error {
	return nil
}

// Network
func (ext *testExternal) postMsg(msg *channelMsg) {
	ext.clusterChan <- msg
}
func (ext *testExternal) Broadcast(msg *pb.ConsensusMessage) error {
	if !ext.testNode.online {
		return errors.New("node offline")
	}

	cm := &channelMsg{
		msg: msg,
		to:  "",
	}

	go ext.postMsg(cm)
	return nil
}
func (ext *testExternal) Unicast(msg *pb.ConsensusMessage, to uint64) error {
	if !ext.testNode.online {
		return errors.New("node offline")
	}

	cm := &channelMsg{
		msg: msg,
	}

	for _, peer := range ext.testNode.Router.Peers {
		if peer.Id == to {
			cm.to = peer.Hash
			break
		}
	}

	go ext.postMsg(cm)
	return nil
}
func (ext *testExternal) UnicastByHash(msg *pb.ConsensusMessage, to string) error {
	if !ext.testNode.online {
		return errors.New("node offline")
	}

	cm := &channelMsg{
		msg: msg,
		to:  to,
	}

	go ext.postMsg(cm)
	return nil
}
func (ext *testExternal) UpdateTable(update *pb.ConfChange) {
	router := update.Router
	var newPeers []*pb.Peer
	for _, peer := range router.Peers {
		newPeer := &pb.Peer{
			Id:       peer.Id,
			Hostname: peer.Hostname,
			Hash:     hash(peer.Hostname),
		}
		newPeers = append(newPeers, newPeer)
	}
	newRouter := &pb.Router{Peers: newPeers}
	ext.testNode.Router = getRouter(router)
	ext.tf.log.Noticef("[Cluster_Service %s update] router: %+v", ext.testNode.Hostname, newRouter)
	cc := &pb.ConfState{QuorumRouter: newRouter}
	ext.testNode.N.ApplyConfChange(cc)
}

// Crypto
func (ext *testExternal) Sign(msg []byte) ([]byte, error) {
	return nil, nil
}
func (ext *testExternal) Verify(peerID uint64, signature []byte, msg []byte) error {
	return nil
}

// ServiceOutbound
func (ext *testExternal) Execute(requests []*protos.Transaction, localList []bool, seqNo uint64, timestamp int64) {
	var txHashList []string
	for _, req := range requests {
		txHash := requestHash(req)
		txHashList = append(txHashList, txHash)
	}
	batchDigest := calculateMD5Hash(txHashList, timestamp)

	state := &pb.ServiceState{}
	state.MetaState = &pb.MetaState{
		Applied: seqNo,
		Digest:  batchDigest,
	}

	if state.MetaState.Applied == ext.testNode.Applied+1 {
		ext.testNode.Applied = state.MetaState.Applied
		ext.testNode.Digest = state.MetaState.Digest
		ext.testNode.blocks[state.MetaState.Applied] = state.MetaState.Digest
		ext.testNode.n.logger.Debugf("Block Number %d", state.MetaState.Applied)
		ext.testNode.n.logger.Debugf("Block Hash %s", state.MetaState.Digest)
		//report latest validator set
		if len(requests) != 0 {
			if protos.IsConfigTx(requests[0]) {
				r := &pb.Router{}
				_ = proto.Unmarshal(requests[0].Value, r)
				ext.testNode.vset[state.MetaState.Applied] = *r
				ext.testNode.n.logger.Debugf("Epoch Number %d", state.MetaState.Applied)
				ext.testNode.n.logger.Debugf("Validator Set %+v", r)
				re := &pb.ReloadMessage{
					Type:   pb.ReloadType_FinishReloadRouter,
					Router: r,
				}
				ext.testNode.N.ReportReloadFinished(re)
			}
		}
		// report executed
		go ext.testNode.N.ReportExecuted(state)
	}
}
func (ext *testExternal) StateUpdate(seqNo uint64, digest string, peers []uint64) {
	vSet := make(map[uint64]string)
	for key, val := range ext.tf.TestNode[0].vset {
		if key <= seqNo {
			ext.testNode.vset[key] = val
			routerInfo, _ := proto.Marshal(&val)
			vSet[key] = byte2Hex(routerInfo)

			if key > ext.testNode.Epoch {
				ext.testNode.Epoch = key
				ext.testNode.Router = val
			}
		}
	}

	for key, val := range ext.tf.TestNode[0].blocks {
		if key <= seqNo {
			ext.testNode.blocks[key] = val
			ext.testNode.n.logger.Debugf("Block Number %d", key)
			ext.testNode.n.logger.Debugf("Block Hash %s", val)

			if key > ext.testNode.Applied {
				ext.testNode.Applied = key
				ext.testNode.Digest = val
			}
		}
	}

	state := &pb.ServiceState{}
	state.MetaState = &pb.MetaState{
		Applied: ext.testNode.Applied,
		Digest:  ext.testNode.Digest,
	}
	ext.testNode.N.ReportStateUpdated(state)
}
func (ext *testExternal) SendFilterEvent(informType pb.InformType, message ...interface{}) {
	if ext.testNode.n.rbft.atomicIn(InConfChange) {
		height, ok := message[0].(uint64)
		if !ok {
			return
		}

		switch informType {
		case pb.InformType_FilterStableCheckpoint:
			re := &pb.ReloadMessage{
				Type:   pb.ReloadType_FinishReloadCommitDB,
				Height: height,
			}
			go ext.testNode.N.ReportReloadFinished(re)
		}
	}
}

//=============================================================================
// Tools for Cluster Check Stable State
//=============================================================================

// set N/f of cluster
func (tf *testFramework) setN(num int) {
	tf.NLock.Lock()
	defer tf.NLock.Unlock()
	tf.N = num
	tf.f = (tf.N - 1) / 3
}

func hash(hostname string) string {
	return "hash-" + hostname
}