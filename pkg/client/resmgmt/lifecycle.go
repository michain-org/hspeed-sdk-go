package resmgmt

import (
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

const (
	lifecycleName                   = "_lifecycle"
	installFuncName                 = "InstallChaincode"
	queryInstalledFuncName          = "QueryInstalledChaincodes"
	getInstalledPackageFuncName     = "GetInstalledPackage"
	approveFuncName                 = "ApproveChaincodeDefinitionForMyOrg"
	commitFuncName                  = "CommitChaincodeDefinition"
	checkCommitReadinessFuncName    = "CheckCommitReadiness"
	queryChaincodeFuncName          = "QueryChaincodeDefinition"
	queryChaincodesFuncName         = "QueryChaincodeDefinitions"
)

func CreatePolicyBytes(signaturePolicy, channelConfigPolicy string) ([]byte, error) {
	if signaturePolicy == "" && channelConfigPolicy == "" {
		// no policy, no problem
		return nil, nil
	}

	if signaturePolicy != "" && channelConfigPolicy != "" {
		// mo policies, mo problems
		return nil, errors.New("cannot specify both \"--signature-policy\" and \"--channel-config-policy\"")
	}

	var applicationPolicy *pb.ApplicationPolicy
	if signaturePolicy != "" {
		signaturePolicyEnvelope, err := cauthdsl.FromString(signaturePolicy)
		if err != nil {
			return nil, errors.Errorf("invalid signature policy: %s", signaturePolicy)
		}

		applicationPolicy = &pb.ApplicationPolicy{
			Type: &pb.ApplicationPolicy_SignaturePolicy{
				SignaturePolicy: signaturePolicyEnvelope,
			},
		}
	}

	if channelConfigPolicy != "" {
		applicationPolicy = &pb.ApplicationPolicy{
			Type: &pb.ApplicationPolicy_ChannelConfigPolicyReference{
				ChannelConfigPolicyReference: channelConfigPolicy,
			},
		}
	}

	policyBytes := protoutil.MarshalOrPanic(applicationPolicy)
	return policyBytes, nil
}
