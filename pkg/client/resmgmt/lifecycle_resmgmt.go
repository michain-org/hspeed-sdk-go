package resmgmt

import (
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	lb "github.com/hyperledger/fabric-protos-go/peer/lifecycle"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/errors/multi"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/context"
	"github.com/michain-org/hspeed-sdk-go/pkg/common/providers/fab"
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
	proposalResponse, err := rc.SignAndSendProposal(proposal, options)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign and send proposal")
	}
	response := &lb.InstallChaincodeResult{}
	if len(proposalResponse) > 0 {
		err = proto.Unmarshal(proposalResponse[0].Response.Payload, response)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal to InstallChaincodeResult")
		}
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
	_, err = rc.SignAndSendProposal(proposal, options)
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
	_, err = rc.SignAndSendProposal(proposal, options)
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
	proposalResponse, err := rc.SignAndSendProposal(proposal, options)

	response := &lb.ApproveChaincodeDefinitionForMyOrgResult{}
	if len(proposalResponse) > 0 {
		err = proto.Unmarshal(proposalResponse[0].Response.Payload, response)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal to InstallChaincodeResult")
		}
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
	_, err = rc.SignAndSendProposal(proposal, options)
	return err
}

func (rc *Client) LifecycleCommit(args *lb.CommitChaincodeDefinitionArgs, channelID string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createCommitProposal(args, channelID, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	_, err = rc.SignAndSendProposal(proposal, options)
	return err
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
	_, err = rc.SignAndSendProposal(proposal, options)
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

func (rc *Client) SignAndSendProposal(proposal *pb.Proposal, options []RequestOption) ([]*fab.TransactionProposalResponse, error) {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get opts for InstantiateCC")
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
		wg.Add(1)
		go func(processor fab.ProposalProcessor) {
			defer wg.Done()

			// TODO: The RPC should be timed-out.
			//resp, err := processor.ProcessTransactionProposal(context.NewRequestOLD(ctx), request)
			resp, err := processor.ProcessTransactionProposal(reqCtx, request)
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
