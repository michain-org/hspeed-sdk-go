package resmgmt

import (
	reqContext "context"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	lb "github.com/hyperledger/fabric-protos-go/peer/lifecycle"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/context"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/fab"
	"github.com/michain-org/hspeed-sdk-go/pkg/fab/txn"
	"github.com/pkg/errors"
)

func (rc *Client) NewInstallArgs(ccBytes []byte) (*lb.InstallChaincodeArgs, error) {
	return &lb.InstallChaincodeArgs{
		ChaincodeInstallPackage: ccBytes,
	}, nil
}

func (rc *Client) NewApproveForMyOrgProposalArgs(name string, v string, sequence int64, ep string, vp string, sp string, cp string,
	packageID string, collectionsBytes []byte, initRequired bool) (*lb.ApproveChaincodeDefinitionForMyOrgArgs, error) {
	policyBytes, err := createPolicyBytes(sp, cp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create policy bytes")
	}

	collections, err := createCollectionConfigPackage(collectionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create collections")
	}

	var ccsrc *lb.ChaincodeSource
	if packageID != "" {
		ccsrc = &lb.ChaincodeSource{
			Type: &lb.ChaincodeSource_LocalPackage{
				LocalPackage: &lb.ChaincodeSource_Local{
					PackageId: packageID,
				},
			},
		}
	} else {
		ccsrc = &lb.ChaincodeSource{
			Type: &lb.ChaincodeSource_Unavailable_{
				Unavailable: &lb.ChaincodeSource_Unavailable{},
			},
		}
	}
	return &lb.ApproveChaincodeDefinitionForMyOrgArgs{
		Sequence:            sequence,
		Name:                name,
		Version:             v,
		EndorsementPlugin:   ep,
		ValidationPlugin:    vp,
		ValidationParameter: policyBytes,
		Collections:         collections,
		InitRequired:        initRequired,
		Source:              ccsrc,
	}, nil
}

func (rc *Client) NewCommitChaincodeDefinitionArgs(name string, v string, sequence int64, ep string, vp string, sp string, cp string,
	collectionsBytes []byte, initRequired bool) (*lb.CommitChaincodeDefinitionArgs, error) {
	policyBytes, err := createPolicyBytes(sp, cp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create policy bytes")
	}

	collections, err := createCollectionConfigPackage(collectionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create collections")
	}

	return &lb.CommitChaincodeDefinitionArgs{
		Sequence:            sequence,
		Name:                name,
		Version:             v,
		EndorsementPlugin:   ep,
		ValidationPlugin:    vp,
		ValidationParameter: policyBytes,
		Collections:         collections,
		InitRequired:        initRequired,
	}, nil
}

func (rc *Client) NewQueryCommitted() (*lb.QueryChaincodeDefinitionsArgs, error) {
	return &lb.QueryChaincodeDefinitionsArgs{}, nil
}

func (rc *Client) NewQueryCommittedWithName(name string) (*lb.QueryChaincodeDefinitionArgs, error) {
	return &lb.QueryChaincodeDefinitionArgs{Name: name}, nil
}

func (rc *Client) LifecycleInstall(args []byte, channelID string, options ...RequestOption) (*lb.InstallChaincodeResult, error) {
	proposalResponses, err := rc.ProcessTransactionProposal(args, installFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.InstallChaincodeResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleQueryInstalled(args []byte, channelID string, options ...RequestOption) (*lb.QueryInstalledChaincodeResult, error) {
	proposalResponses, err := rc.submitProposal(args, queryInstalledFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.QueryInstalledChaincodeResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleGetInstalledPackage(args []byte, channelID string, options ...RequestOption) (*lb.GetInstalledChaincodePackageResult, error) {
	proposalResponses, err := rc.submitProposal(args, getInstalledPackageFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.GetInstalledChaincodePackageResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleApproveForMyOrg(args []byte, channelID string, options ...RequestOption) (*lb.ApproveChaincodeDefinitionForMyOrgResult, error) {
	proposalResponses, err := rc.submitProposal(args, approveFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.ApproveChaincodeDefinitionForMyOrgResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleCheckCommitReadiness(args []byte, channelID string, options ...RequestOption) (*lb.CheckCommitReadinessResult, error) {
	proposalResponses, err := rc.submitProposal(args, checkCommitReadinessFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.CheckCommitReadinessResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleCommit(args []byte, channelID string, options ...RequestOption) (*lb.CommitChaincodeDefinitionResult, error) {
	proposalResponses, err := rc.submitProposal(args, commitFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.CommitChaincodeDefinitionResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleQueryCommitted(args []byte, channelID string, options ...RequestOption) (*lb.QueryChaincodeDefinitionsResult, error) {
	proposalResponses, err := rc.ProcessTransactionProposal(args, queryChaincodesFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.QueryChaincodeDefinitionsResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) LifecycleQueryCommittedWithName(args []byte, channelID string, options ...RequestOption) (*lb.QueryChaincodeDefinitionResult, error) {
	proposalResponses, err := rc.ProcessTransactionProposal(args, queryChaincodeFuncName, channelID, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	response := &lb.QueryChaincodeDefinitionResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode approve failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode approve failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to ApproveChaincodeDefinitionForMyOrgResult")
	}

	return response, err
}

func (rc *Client) signProposal(proposal *pb.Proposal, ctx context.Client) (*pb.SignedProposal, error) {
	// check for nil argument
	if proposal == nil {
		return nil, errors.New("proposal cannot be nil")
	}

	proposalBytes, err := proto.Marshal(proposal)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling proposal")
	}

	signingMgr := ctx.SigningManager()
	signature, err := signingMgr.Sign(proposalBytes, ctx.PrivateKey())
	if err != nil {
		return nil, err
	}

	return &pb.SignedProposal{
		ProposalBytes: proposalBytes,
		Signature:     signature,
	}, nil
}

func (rc *Client) createProposal(argsBytes []byte, funcName string, channelID string, txID *txn.TransactionHeader) (*pb.Proposal, error) {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signer")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(funcName), argsBytes}}
	cis := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{Name: lifecycleName},
			Input:       ccInput,
		},
	}

	proposal, _, err := protoutil.CreateChaincodeProposalWithTxIDNonceAndTransient(string(txID.TransactionID()), cb.HeaderType_ENDORSER_TRANSACTION, channelID, cis, txID.Nonce(), serializedSigner, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create proposal for ChaincodeInvocationSpec")
	}

	return proposal, nil
}

func (rc *Client) ProcessTransactionProposal(args []byte, funcName string, channelID string, options []RequestOption) ([]*fab.TransactionProposalResponse, error) {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get opts for InstantiateCC")
	}

	reqCtx, cancel := rc.createRequestContext(opts, fab.ResMgmt)
	defer cancel()

	targets, err := rc.getCCProposalTargets(channelID, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get targets")
	}

	txID, err := txn.NewHeader(rc.ctx, channelID)
	if err != nil {
		return nil, errors.WithMessage(err, "create transaction ID failed")
	}

	proposal, _ := rc.createProposal(args, funcName, channelID, txID)

	txProposal := &fab.TransactionProposal{
		TxnID:    txID.TransactionID(),
		Proposal: proposal,
	}

	channelService, err := rc.ctx.ChannelProvider().ChannelService(rc.ctx, channelID)
	if err != nil {
		return nil, errors.WithMessage(err, "Unable to get channel service")
	}

	transactor, err := channelService.Transactor(reqCtx)
	if err != nil {
		return nil, errors.WithMessage(err, "get channel transactor failed")
	}

	responses, err := transactor.SendTransactionProposal(txProposal, peersToTxnProcessors(targets))
	if err != nil {
		return nil, errors.WithMessage(err, "send proposal failed")
	}

	return responses, nil
}

func (rc *Client) submitProposal(args []byte, funcName string, channelID string, options []RequestOption) ([]*fab.TransactionProposalResponse, error) {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get opts for InstantiateCC")
	}

	reqCtx, cancel := rc.createRequestContext(opts, fab.ResMgmt)
	defer cancel()

	targets, err := rc.getCCProposalTargets(channelID, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get targets")
	}

	txID, err := txn.NewHeader(rc.ctx, channelID)
	if err != nil {
		return nil, errors.WithMessage(err, "create transaction ID failed")
	}

	proposal, _ := rc.createProposal(args, funcName, channelID, txID)

	txProposal := &fab.TransactionProposal{
		TxnID:    txID.TransactionID(),
		Proposal: proposal,
	}

	channelService, err := rc.ctx.ChannelProvider().ChannelService(rc.ctx, channelID)
	if err != nil {
		return nil, errors.WithMessage(err, "Unable to get channel service")
	}

	transactor, err := channelService.Transactor(reqCtx)
	if err != nil {
		return nil, errors.WithMessage(err, "get channel transactor failed")
	}

	eventService, err := channelService.EventService()
	if err != nil {
		return nil, errors.WithMessage(err, "unable to get event service")
	}

	return rc.SendTransactionAndCheckEvent(eventService, transactor, reqCtx, targets, txProposal)
}

func (rc *Client) SendTransactionAndCheckEvent(service fab.EventService, transactor fab.Transactor, reqCtx reqContext.Context, targets []fab.Peer, proposal *fab.TransactionProposal) ([]*fab.TransactionProposalResponse, error) {
	// Register for commit event
	reg, statusNotifier, err := service.RegisterTxStatusEvent(string(proposal.TxnID))
	if err != nil {
		return nil, errors.WithMessage(err, "error registering for TxStatus event")
	}
	defer service.Unregister(reg)

	responses, err := transactor.SendTransactionProposal(proposal, peersToTxnProcessors(targets))
	if err != nil {
		return nil, errors.WithMessage(err, "send proposal failed")
	}

	txnRequest := fab.TransactionRequest{
		Proposal:          proposal,
		ProposalResponses: responses,
	}

	tx, err := transactor.CreateTransaction(txnRequest)
	if err != nil {
		return nil, errors.WithMessage(err, "create transation failed")
	}

	_, err = transactor.SendTransaction(tx)
	if err != nil {
		return nil, errors.WithMessage(err, "send transation failed")
	}

	select {
	case txStatus := <-statusNotifier:
		if txStatus.TxValidationCode == pb.TxValidationCode_VALID {
			return responses, nil
		}
		return nil, errors.Errorf("tx[%s] execute failed", txStatus.TxID)
	case <-reqCtx.Done():
		return nil, errors.New("Execute timed out or cancelled")
	}
}
