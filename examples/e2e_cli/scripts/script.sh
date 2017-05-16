#!/bin/bash

CHANNEL_NAME="$3"
: ${CHANNEL_NAME:="mychannel"}
: ${TIMEOUT:="60"}
ORGS=$1
PEERNODES=$2
COUNTER=0
MAX_RETRY=5
ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config-tls/ordererOrganizations/ordererOrg1/orderers/ordererorg1orderer1/cacerts/ordererOrg1-cert.pem
#PAUSE=read

echo "Channel name : "$CHANNEL_NAME

verifyResult () {
	if [ $1 -ne 0 ] ; then
		echo "!!!!!!!!!!!!!!! "$2" !!!!!!!!!!!!!!!!"
                echo "================== ERROR !!! FAILED to execute End-2-End Scenario =================="
		echo
   		exit 1
	fi
}

setGlobals () {
	org=$1
	peer=$2

	#export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/users/Admin@peerOrg${org}
	CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/peers/peerorg${org}peer${peer}
	CORE_PEER_ADDRESS=peerorg${org}peer${peer}:7051
	CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricpeerOrg${org}Peer${peer}
	#export CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricAdminpeerOrg${org}

	CORE_PEER_LOCALMSPID="Org${org}MSP"
	CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/peers/peerorg${org}peer${peer}/cacerts/tls-peerorg${org}-cert.pem
	env |grep CORE
}

setGlobalsForAdmins () {
	org=$1
	peer=$2

	CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/users/Admin@peerOrg${org}
	#export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/peers/peerOrg${org}Peer${peer}
	CORE_PEER_ADDRESS=peerorg${org}peer${peer}:7051
	#export CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricpeerOrg${org}Peer${peer}
	CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricAdminpeerOrg${org}

	CORE_PEER_LOCALMSPID="Org${org}MSP"
	CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/peers/peerorg${org}peer${peer}/cacerts/tls-peerOrg${org}-cert.pem
	env |grep CORE
}

createChannel() {
	org=$1
	peer=1
	
	#export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/peers/peerOrg${org}Peer${peer}
	export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg${org}/users/Admin@peerOrg${org}
 	export CORE_PEER_LOCALMSPID="Org${org}MSP"
	export CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricAdminpeerOrg${org}
	#export CORE_PEER_BCCSP_PKCS11_LABEL=ForFabricpeerOrg${org}Peer${peer}

	env |grep CORE
	
    if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
		peer channel create -o ordererorg1orderer1:7050 -c $CHANNEL_NAME -f crypto-config/channel.tx >&log.txt
	else
		echo "peer channel create -o ordererorg1orderer1:7050 -c $CHANNEL_NAME -f crypto-config/channel.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA"
		peer channel create -o ordererorg1orderer1:7050 -c $CHANNEL_NAME -f crypto-config/channel.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA >&log.txt
	fi
	res=$?
	cat log.txt
	verifyResult $res "Channel creation failed"
	echo "===================== Channel \"$CHANNEL_NAME\" is created successfully ===================== "
	echo
	${PAUSE}
}

updateAnchorPeers() {
    org=$1
	peer=$2
	
	setGlobalsForAdmins ${org} ${peer}

    if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
		peer channel create -o ordererorg1orderer1:7050 -c $CHANNEL_NAME -f crypto-config/${CORE_PEER_LOCALMSPID}anchors.tx >&log.txt
	else
		peer channel create -o ordererorg1orderer1:7050 -c $CHANNEL_NAME -f crypto-config/${CORE_PEER_LOCALMSPID}anchors.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA >&log.txt
	fi
	res=$?
	cat log.txt
	verifyResult $res "Anchor peer update failed"
	echo "===================== Anchor peers for org \"$CORE_PEER_LOCALMSPID\" on \"$CHANNEL_NAME\" is updated successfully ===================== "
	echo
	${PAUSE}
}

## Sometimes Join takes time hence RETRY atleast for 5 times
joinWithRetry () {
	org=$1
	peer=$2
	
	echo "peer channel join -b $CHANNEL_NAME.block"
	peer channel join -b $CHANNEL_NAME.block  >&log.txt
	res=$?
	cat log.txt
	if [ $res -ne 0 -a $COUNTER -lt $MAX_RETRY ]; then
		COUNTER=` expr $COUNTER + 1`
		echo "PEER${peer} from Org${org} failed to join the channel, Retry after 2 seconds"
		sleep 2
		joinWithRetry ${org} ${peer}
	else
		COUNTER=0
	fi
        verifyResult $res "After $MAX_RETRY attempts, PEER${peer} from Org${org} has failed to Join the Channel"
}

joinChannel () {
	for ORG in $(seq 1 ${ORGS})
	do
		for PEER in $(seq 1 ${PEERNODES})
		do
			setGlobalsForAdmins ${ORG} ${PEER}
			joinWithRetry ${ORG} ${PEER}
			echo "===================== PEER${PEER} from Org${ORG} joined on the channel \"$CHANNEL_NAME\" ===================== "
			sleep 2
			echo
			${PAUSE}
		done
	done
}

installChaincode () {
	org=$1
	peer=$2
	
	setGlobalsForAdmins ${org} ${peer}
	peer chaincode install -n mycc -v 1.0 -p github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02 >&log.txt
	res=$?
	cat log.txt
        verifyResult $res "Chaincode installation on remote peer PEER${peer} from Org${org} has Failed"
	echo "===================== Chaincode is installed on remote peer PEER${peer} from Org${org} ===================== "
	echo
	${PAUSE}
}

instantiateChaincode () {
	org=$1
	peer=$2
	
	setGlobals ${org} ${peer}
    if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
		peer chaincode instantiate -o ordererorg1orderer1:7050 -C $CHANNEL_NAME -n mycc -v 1.0 -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.member','Org2MSP.member')" >&log.txt
	else
		peer chaincode instantiate -o ordererorg1orderer1:7050 --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n mycc -v 1.0 -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.member','Org2MSP.member')" >&log.txt
	fi
	res=$?
	cat log.txt
	verifyResult $res "Chaincode instantiation on PEER$PEER on channel '$CHANNEL_NAME' failed"
	echo "===================== Chaincode Instantiation on PEER${peer} from Org${org} on channel '$CHANNEL_NAME' is successful ===================== "
	echo
	${PAUSE}
}

chaincodeQuery () {
  org=$1
  peer=$2
	
  echo "===================== Querying on PEER${peer} from Org${org} on channel '$CHANNEL_NAME'... ===================== "
  setGlobals ${org} ${peer}
  local rc=1
  local starttime=$(date +%s)

  # continue to poll
  # we either get a successful response, or reach TIMEOUT
  while test "$(($(date +%s)-starttime))" -lt "$TIMEOUT" -a $rc -ne 0
  do
     sleep 3
     echo "Attempting to Query PEER${peer} from Org${org} ...$(($(date +%s)-starttime)) secs"
     peer chaincode query -C $CHANNEL_NAME -n mycc -c '{"Args":["query","a"]}' >&log.txt
     test $? -eq 0 && VALUE=$(cat log.txt | awk '/Query Result/ {print $NF}')
     test "$VALUE" = "$3" && let rc=0
  done
  echo
  cat log.txt
  if test $rc -eq 0 ; then
	echo "===================== Query on PEER${peer} from Org${org} on channel '$CHANNEL_NAME' is successful ===================== "
  else
	echo "!!!!!!!!!!!!!!! Query result on PEER${peer} from Org${org} is INVALID !!!!!!!!!!!!!!!!"
        echo "================== ERROR !!! FAILED to execute End-2-End Scenario =================="
	echo
  fi
}

chaincodeInvoke () {
	org=$1
	peer=$2
	
    if [ -z "$CORE_PEER_TLS_ENABLED" -o "$CORE_PEER_TLS_ENABLED" = "false" ]; then
		peer chaincode invoke -o ordererorg1orderer1:7050 -C $CHANNEL_NAME -n mycc -c '{"Args":["invoke","a","b","10"]}' >&log.txt
	else
		peer chaincode invoke -o ordererorg1orderer1:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C $CHANNEL_NAME -n mycc -c '{"Args":["invoke","a","b","10"]}' >&log.txt
	fi
	res=$?
	cat log.txt
	verifyResult $res "Invoke execution on PEER${peer} from Org${org} failed "
	echo "===================== Invoke transaction on PEER$PEER on channel '$CHANNEL_NAME' is successful ===================== "
	echo
	${PAUSE}
}


## Create channel
createChannel 1 1

## Join all the peers to the channel
joinChannel

## Set the anchor peers for each org in the channel
for ORG in $(seq 1 ${ORGS})
do
    updateAnchorPeers ${ORG} 1
done

## Install chaincode on Peer1/Org1 and Peer1/Org2
for ORG in $(seq 1 ${ORGS})
do
    installChaincode ${ORG} 1
done

#Instantiate chaincode on Peer2/Org1
echo "Instantiating chaincode on Peer1/Org2 ..."
instantiateChaincode 2 1

#Query on chaincode on Peer1/Org1
chaincodeQuery 1 1 100

#Invoke on chaincode on Peer1/Org1
echo "send Invoke transaction on Peer1/Org1 ..."
chaincodeInvoke 1 1

## Install chaincode on Peer2/Org2
installChaincode 2 2

#Query on chaincode on Peer2/Org2, check if the result is 90
chaincodeQuery 2 2 90

echo
echo "===================== All GOOD, End-2-End execution completed ===================== "
echo
exit 0
