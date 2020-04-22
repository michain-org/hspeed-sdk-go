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

func (rc *Client) createProposal(input *pb.ChaincodeInput, creator []byte) (*pb.Proposal, error) {
	cis := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{ Name: lifecycleName },
			Input:       input,
		},
	}
	proposal, _, err := protoutil.CreateProposalFromCIS(cb.HeaderType_ENDORSER_TRANSACTION, "", cis, creator)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create proposal for ChaincodeInvocationSpec")
	}
	return proposal, nil
}

func (rc *Client) createInstallProposal(pkgBytes []byte, creator []byte) (*pb.Proposal, error) {
	args := &lb.InstallChaincodeArgs{
		ChaincodeInstallPackage: pkgBytes,
	}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(installFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createQueryInstalledProposal(creator []byte) (*pb.Proposal, error) {
	args := &lb.QueryInstalledChaincodeArgs{}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(queryInstalledFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createGetInstalledPackageProposal(packageID string, creator []byte) (*pb.Proposal, error) {
	args := &lb.GetInstalledChaincodePackageArgs{ PackageId: packageID }
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(getInstalledPackageFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createApproveForMyOrgProposal(args *lb.ApproveChaincodeDefinitionForMyOrgArgs, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(approveFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createCheckCommitReadinessProposal(args *lb.CheckCommitReadinessArgs, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(checkCommitReadinessFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createCommitProposal(args *lb.CommitChaincodeDefinitionArgs, creator []byte) (*pb.Proposal, error) {
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(commitFuncName), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) createQueryCommittedProposal(name string, creator []byte) (*pb.Proposal, error) {
	var function string
	var args proto.Message
	if name == "" {
		function = queryChaincodesFuncName
		args = &lb.QueryChaincodeDefinitionsArgs{}
	} else {
		function = queryChaincodeFuncName
		args = &lb.QueryChaincodeDefinitionArgs{ Name: name }
	}
	argsBytes, err := proto.Marshal(args)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal args")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte(function), argsBytes}}
	return rc.createProposal(ccInput, creator)
}

func (rc *Client) LifecycleInstallChaincode(pkgBytes []byte, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createInstallProposal(pkgBytes, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create install proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleQueryChaincodeInstalled(options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createQueryInstalledProposal(serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create query installed proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleGetInstalledPackage(packageId string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createGetInstalledPackageProposal(packageId, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create query installed proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleApproveForMyOrg(args *lb.ApproveChaincodeDefinitionForMyOrgArgs, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createApproveForMyOrgProposal(args, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleCheckCommitReadiness(args *lb.CheckCommitReadinessArgs, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createCheckCommitReadinessProposal(args, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleCommit(args *lb.CommitChaincodeDefinitionArgs, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createCommitProposal(args, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
}

func (rc *Client) LifecycleQueryCommitted(name string, options ...RequestOption) error {
	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createQueryCommittedProposal(name, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create approve proposal")
	}
	return rc.SignAndSendProposal(proposal, options)
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

func (rc *Client) SignAndSendProposal(proposal *pb.Proposal, options []RequestOption) error {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return errors.WithMessage(err, "failed to get opts for InstantiateCC")
	}
	targets := opts.Targets
	signedProposal, err := rc.signProposal(proposal, rc.ctx)
	if err != nil {
		return errors.WithMessage(err, "failed to sign proposal")
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
	if err != nil {
		return errors.WithMessage(err, "failed to create signed proposal for chaincode install")
	}
	return nil
}