package resmgmt

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	lb "github.com/hyperledger/fabric-protos-go/peer/lifecycle"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/errors/multi"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/context"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/fab"
	"github.com/michain-org/hspeed-sdk-go/pkg/fab/txn"
	"github.com/pkg/errors"
	"sync"
)

func (rc *Client) createProposal(input *pb.ChaincodeInput, channelID string, creator []byte) (*pb.Proposal, error) {
	cis := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{Name: lifecycleName},
			Input:       input,
		},
	}
	proposal, _, err := protoutil.CreateProposalFromCIS(cb.HeaderType_ENDORSER_TRANSACTION, channelID, cis, creator)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create proposal for ChaincodeInvocationSpec")
	}

	return proposal, nil
}

func (rc *Client) createInstallProposal(pkgBytes []byte, channelID string, creator []byte) (*pb.Proposal, error) {
	args := &lb.InstallChaincodeArgs{
		ChaincodeInstallPackage: pkgBytes,
	}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(installFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) createQueryInstalledProposal(channelID string, creator []byte) (*pb.Proposal, error) {
	args := &lb.QueryInstalledChaincodeArgs{}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(queryInstalledFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) createGetInstalledPackageProposal(packageID string, channelID string, creator []byte) (*pb.Proposal, error) {
	args := &lb.GetInstalledChaincodePackageArgs{PackageId: packageID}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(getInstalledPackageFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
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

func (rc *Client) createApproveForMyOrgProposal(args *lb.ApproveChaincodeDefinitionForMyOrgArgs, channelID string, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(approveFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) createCheckCommitReadinessProposal(args *lb.CheckCommitReadinessArgs, channelID string, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(checkCommitReadinessFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) createCommitProposal(args *lb.CommitChaincodeDefinitionArgs, channelID string, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(commitFuncName), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) createQueryCommittedProposal(name string, channelID string, creator []byte) (*pb.Proposal, error) {
	var function string
	var args proto.Message
	if name == "" {
		function = queryChaincodesFuncName
		args = &lb.QueryChaincodeDefinitionsArgs{}
	} else {
		function = queryChaincodeFuncName
		args = &lb.QueryChaincodeDefinitionArgs{Name: name}
	}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}

	ccInput := &pb.ChaincodeInput{Args: [][]byte{[]byte(function), argsBytes}}
	return rc.createProposal(ccInput, channelID, creator)
}

func (rc *Client) LifecycleInstall(pkgBytes []byte, channelID string, options ...RequestOption) (*lb.InstallChaincodeResult, error) {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createInstallProposal(pkgBytes, channelID, serializedSigner)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create install proposal")
	}

	proposalResponses, err := rc.ProcessTransactionProposal(proposal, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign and send proposal")
	}

	response := &lb.InstallChaincodeResult{}
	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode install failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode install failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to InstallChaincodeResult")
	}
	return response, err
}

func (rc *Client) LifecycleQueryInstalled(channelID string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createQueryInstalledProposal(channelID, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create query installed proposal")
	}

	_, err = rc.ProcessTransactionProposal(proposal, options)
	return err
}

func (rc *Client) LifecycleGetInstalledPackage(packageId string, channelID string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createGetInstalledPackageProposal(packageId, channelID, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create query installed proposal")
	}

	_, err = rc.ProcessTransactionProposal(proposal, options)
	return err
}

func (rc *Client) LifecycleApproveForMyOrg(args *lb.ApproveChaincodeDefinitionForMyOrgArgs, channelID string, options ...RequestOption) (*lb.ApproveChaincodeDefinitionForMyOrgResult, error) {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createApproveForMyOrgProposal(args, channelID, serializedSigner)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create approve proposal")
	}

	proposalResponses, err := rc.ProcessTransactionProposal(proposal, options)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to send approve proposal")
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

	err = rc.submitProposal(proposal, channelID, options, proposalResponses)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}

	return response, err
}

func (rc *Client) LifecycleCheckCommitReadiness(args *lb.CheckCommitReadinessArgs, channelID string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createCheckCommitReadinessProposal(args, channelID, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	_, err = rc.ProcessTransactionProposal(proposal, options)
	return err
}

func (rc *Client) LifecycleCommit(args *lb.CommitChaincodeDefinitionArgs, channelID string, options ...RequestOption) (*lb.CommitChaincodeDefinitionResult, error) {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createCommitProposal(args, channelID, serializedSigner)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create approve proposal")
	}

	response := &lb.CommitChaincodeDefinitionResult{}
	proposalResponses, err := rc.ProcessTransactionProposal(proposal, options)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to send commit proposal")
	}

	if len(proposalResponses) == 0 {
		return nil, errors.New("chaincode commit failed: received proposal response with nil response")

	}
	if proposalResponses[0].Status != int32(cb.Status_SUCCESS) {
		return nil, errors.Errorf("chaincode commit failed with status %d - %s", proposalResponses[0].Response.Status, proposalResponses[0].Response.Message)
	}
	err = proto.Unmarshal(proposalResponses[0].Response.Payload, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal to CommitChaincodeDefinitionResult")
	}

	err = rc.submitProposal(proposal, channelID, options, proposalResponses)
	if err != nil {
		return nil, errors.Wrap(err, "failed when submit proposal")
	}
	return response, err
}

func (rc *Client) LifecycleQueryCommitted(name string, channelID string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}

	proposal, err := rc.createQueryCommittedProposal(name, channelID, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	_, err = rc.ProcessTransactionProposal(proposal, options)
	return err
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

func (rc *Client) ProcessTransactionProposal(proposal *pb.Proposal, options []RequestOption) ([]*fab.TransactionProposalResponse, error) {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get opts")
	}
	targets := opts.Targets

	signedProposal, err := rc.signProposal(proposal, rc.ctx)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to sign proposal")
	}

	request := fab.ProcessProposalRequest{SignedProposal: signedProposal}
	reqCtx, cancel := rc.createRequestContext(opts, fab.ResMgmt)
	defer cancel()

	var responseMtx sync.Mutex
	var transactionProposalResponses []*fab.TransactionProposalResponse
	var wg sync.WaitGroup
	errs := multi.Errors{}
	for _, p := range targets {
		fmt.Println(p.URL())
		wg.Add(1)
		go func(processor fab.ProposalProcessor) {
			defer wg.Done()

			resp, err := p.ProcessTransactionProposal(reqCtx, request)
			if err != nil {
				logger.Debugf("Received error response from txn proposal processing: %s", err)
				responseMtx.Lock()
				errs = append(errs, err)
				responseMtx.Unlock()
				return
			}

			responseMtx.Lock()
			transactionProposalResponses = append(transactionProposalResponses, resp)
			responseMtx.Unlock()
		}(p)
	}
	wg.Wait()

	return transactionProposalResponses, errs.ToError()
}

func (rc *Client) submitProposal(proposal *pb.Proposal, channelID string, options []RequestOption, responses []*fab.TransactionProposalResponse) error {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return errors.WithMessage(err, "failed to get opts for InstantiateCC")
	}

	reqCtx, cancel := rc.createRequestContext(opts, fab.ResMgmt)
	defer cancel()
	txID, err := txn.NewHeader(rc.ctx, channelID)
	if err != nil {
		return errors.WithMessage(err, "create transaction ID failed")
	}

	txProposal := &fab.TransactionProposal{
		TxnID:    txID.TransactionID(),
		Proposal: proposal,
	}

	txnRequest := fab.TransactionRequest{
		Proposal:          txProposal,
		ProposalResponses: responses,
	}

	channelService, err := rc.ctx.ChannelProvider().ChannelService(rc.ctx, channelID)
	if err != nil {
		return errors.WithMessage(err, "Unable to get channel service")
	}

	transactor, err := channelService.Transactor(reqCtx)
	if err != nil {
		return errors.WithMessage(err, "get channel transactor failed")
	}

	tx, err := transactor.CreateTransaction(txnRequest)
	if err != nil {
		return errors.WithMessage(err, "create transation failed")
	}

	_, err = transactor.SendTransaction(tx)
	if err != nil {
		return errors.WithMessage(err, "send transation failed")
	}
	return nil
}
