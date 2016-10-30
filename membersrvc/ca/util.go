/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"errors"
	mrand "math/rand"
	"time"

	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/membersrvc/protos"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var rnd = mrand.NewSource(time.Now().UnixNano())

func randomString(n int) string {
	b := make([]byte, n)

	for i, cache, remain := n-1, rnd.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rnd.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

//
// MemberRoleToString converts a member role representation from int32 to a string,
// according to the Role enum defined in ca.proto.
//
func MemberRoleToString(role pb.Role) (string, error) {
	roleMap := pb.Role_name

	roleStr := roleMap[int32(role)]
	if roleStr == "" {
		return "", errors.New("Undefined user role passed.")
	}

	return roleStr, nil
}

func ECDSASignDirect(key bccsp.Key, msg []byte) (*big.Int, *big.Int, error) {
	csp, err := bccsp.GetDefault(int(new(CA).GetType())) //just need the type
	if err != nil {
		return nil, nil, err
	}

	signature, err := csp.Sign(key, primitives.Hash(msg), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed generititc signature [%s]", err)
	}

	ecdsaSignature := new(primitives.ECDSASignature)
	_, err = asn1.Unmarshal(signature, ecdsaSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	return ecdsaSignature.R, ecdsaSignature.S, nil

}
