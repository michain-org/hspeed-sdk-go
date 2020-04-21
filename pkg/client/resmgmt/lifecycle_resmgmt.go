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

func (rc *Client) createInstallProposal(pkgBytes []byte, creatorBytes []byte) (*pb.Proposal, error) {
	installChaincodeArgs := &lb.InstallChaincodeArgs{
		ChaincodeInstallPackage: pkgBytes,
	}
	installChaincodeArgsBytes, err := proto.Marshal(installChaincodeArgs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal InstallChaincodeArgs")
	}
	ccInput := &pb.ChaincodeInput{ Args: [][]byte{[]byte("InstallChaincode"), installChaincodeArgsBytes}}
	cis := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{ Name: lifecycleName },
			Input:       ccInput,
		},
	}
	proposal, _, err := protoutil.CreateProposalFromCIS(cb.HeaderType_ENDORSER_TRANSACTION, "", cis, creatorBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create proposal for ChaincodeInvocationSpec")
	}
	return proposal, nil
}

func (rc *Client) LifecycleInstallChanincode(pkgBytes []byte, options ...RequestOption) error {
	opts, err := rc.prepareRequestOpts(options...)
	if err != nil {
		return errors.WithMessage(err, "failed to get opts for InstantiateCC")
	}
	targets := opts.Targets

	serializedSigner, err := rc.ctx.Serialize()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signer")
	}
	proposal, err := rc.createInstallProposal(pkgBytes, serializedSigner)
	if err != nil {
		return errors.WithMessage(err, "failed to create install proposal")
	}
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