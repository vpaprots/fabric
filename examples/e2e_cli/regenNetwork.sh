#!/bin/bash

set -e

# Defaults
#SOFTHSMTOK=${HOME}/softhsm/tokens
SOFTHSMTOK=/var/lib/softhsm/tokens
BASEDIR=.

ORDERERNODES=1
ORGS=2
PEERNODES=2 
USERNODES=1 # Plus Admin

HSM=0
TLS=0
CACHER=0
DEPENDSON=""

function initToken () {
	echo softhsm2-util --init-token --free --label ${PKCS11_LABEL}$1 --so-pin 1234 --pin 98765432
	softhsm2-util --init-token --free --label ${PKCS11_LABEL}$1 --so-pin 1234 --pin 98765432
}

function findTokenDir() {
	label=$1
	token=$(softhsm2-util --show-slots | grep -B 3 ${label} | grep 'Serial number' | sed -e 's/.* \([a-f0-9]\{4\}\)\([a-f0-9]*\).*/\1-\2/')
	token=$(echo ${SOFTHSMTOK}/*${token})
	echo $token:/var/lib/softhsm/tokens/$(basename ${token})
}

function printDockerOrderer() {
	count=$1
	label=$2
	org=$3
	lclabel=$(echo "$label" | tr '[:upper:]' '[:lower:]')
	image="image: hyperledger/fabric-orderer"
	hsmvolume=""
	if [ ${HSM} -ne 0 ]
	then
		hsmvolume="- $(findTokenDir $label)"
		hsmvars=$(cat << EOM
      - ORDERER_GENERAL_BCCSP_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
      - ORDERER_GENERAL_BCCSP_PKCS11_PIN=98765432
      - ORDERER_GENERAL_BCCSP_PKCS11_LABEL=ForFabric${label}
      - ORDERER_GENERAL_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE=/var/hyperledger/orderer/keystore
EOM
)
		image=$(cat << EOM
build:
      context: peer-base
      dockerfile: Dockerfile-hsm-orderer
EOM
)
	fi	
	
	if [ ${TLS} -ne 0 ]
	then
		privatekey=$(find ${BASEDIR}/crypto-config-tls/ordererOrganizations/${org}/orderers/${label}/keystore -name *_sk)
		tlsvars=$(cat << EOM
      # enabled TLS
      - ORDERER_GENERAL_TLS_ENABLED=true
      - ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tlsConfig/keystore/$(basename ${privatekey})
      - ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tlsConfig/signcerts/${label}-cert.pem
      - ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tlsConfig/cacerts/${org}-cert.pem]
EOM
)
	fi	
	
	cat >> docker-compose-gen.yaml << EOM

  $lclabel:
    container_name: $label
    $image
    environment:
      - ORDERER_GENERAL_LOGLEVEL=INFO
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_GENESISMETHOD=file
      - ORDERER_GENERAL_GENESISFILE=/var/hyperledger/orderer/localMspConfig/orderer.block
      - ORDERER_GENERAL_LOCALMSPID=OrdererOrg${count}MSP
      - ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/localMspConfig
${tlsvars}
${hsmvars}
      ${CACHERLINK}
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric
    command: orderer
    volumes:
      - ${BASEDIR}/crypto-config-tls/ordererOrganizations/${org}/orderers/${lclabel}:/var/hyperledger/orderer/tlsConfig
      - ${BASEDIR}/crypto-config/ordererOrganizations/${org}/orderers/${lclabel}:/var/hyperledger/orderer/localMspConfig
      ${hsmvolume}
    ports:
      - 7050:7050

EOM

	DEPENDSON="${DEPENDSON}
      - ${lclabel}"
}

function printDockerPeer() {
	count=$1
	peer=$2
	org=$3
	label=peerOrg${org}Peer${peer}
	orgLabel=peerOrg${org}
	
	lclabel=$(echo "$label" | tr '[:upper:]' '[:lower:]')
	image="image: hyperledger/fabric-peer"
	hsmvolume=""
	bootstrap=""
	portbase=$(expr 6 + ${count})
	
	if [ $peer -ne 1 ]
	then
		bootstrap="- CORE_PEER_GOSSIP_BOOTSTRAP=${label}:7051"
	fi
	
	if [ ${HSM} -ne 0 ]
	then
		hsmvolume="- $(findTokenDir $label)"
		hsmvars=$(cat << EOM
      - CORE_PEER_BCCSP_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
      - CORE_PEER_BCCSP_PKCS11_PIN=98765432
      - CORE_PEER_BCCSP_PKCS11_LABEL=ForFabric${label}
      - CORE_PEER_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE=/var/hyperledger/production/keystore
EOM
)
		image=$(cat << EOM
build:
      context: peer-base
      dockerfile: Dockerfile-hsm-peer
EOM
)
	fi	
	
	if [ ${TLS} -ne 0 ]
	then
		privatekey=$(find ${BASEDIR}/crypto-config-tls/peerOrganizations/${orgLabel}/peers/${label}/keystore -name *_sk)
		tlsvars=$(cat << EOM
      # enabled TLS
      - CORE_PEER_ADDRESSAUTODETECT=false
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tlsConfig/signcerts/${label}-cert.pem
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tlsConfig/keystore/$(basename ${privatekey})
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tlsConfig/cacerts/peerOrg${org}-cert.pem
      # - CORE_PEER_TLS_SERVERHOSTOVERRIDE=peer0
      # The following setting skips the gossip handshake since we are
      # are not doing mutual TLS
      - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
    
EOM
)
	else
		tlsvars=$(cat << EOM
      - CORE_PEER_ADDRESSAUTODETECT=true
      - CORE_PEER_TLS_ENABLED=false
EOM
)
	fi	
	
	
	cat >> docker-compose-gen.yaml << EOM
  $lclabel:
    container_name: $lclabel
    $image
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/peer
    command: peer node start --peer-defaultchain=false #--logging-level=debug:bccsp=debug:bccsp_sw=debug:bccsp_p11=debug:msp=debug
    environment:
      - CORE_PEER_ID=$label
      - CORE_PEER_ADDRESS=$label:7051
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=$label:7051
      $bootstrap
      - CORE_PEER_LOCALMSPID=Org${org}MSP
${tlsvars}
${hsmvars}
    
      # from peer-base/peer-base(-no-tls).yaml
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=e2ecli_default
      - CORE_LOGGING_LEVEL=INFO
      - CORE_NEXT=true
      - CORE_PEER_ENDORSER_ENABLED=true
      - CORE_PEER_GOSSIP_USELEADERELECTION=true
      - CORE_PEER_GOSSIP_ORGLEADER=false
      - CORE_PEER_PROFILE_ENABLED=true    
    volumes:
        - /var/run/:/host/var/run/ #TLS, orderer.block
        - ${BASEDIR}/crypto-config-tls/peerOrganizations/${orgLabel}/peers/${lclabel}:/etc/hyperledger/fabric/tlsConfig
        - ${BASEDIR}/crypto-config/peerOrganizations/${orgLabel}/peers/${lclabel}:/etc/hyperledger/fabric/msp
        ${hsmvolume}
    ports:
      - ${portbase}051:7051
      - ${portbase}053:7053
    depends_on:${DEPENDSON}

EOM

	DEPENDSON="${DEPENDSON}
      - ${lclabel}"
}

function printCliDocker() {
	org=0

	image="image: hyperledger/fabric-testenv"
	hsmvolume=""
	
	if [ ${HSM} -ne 0 ]
	then
		hsmvolume="- $SOFTHSMTOK:/var/lib/softhsm/tokens"
		hsmvars=$(cat << EOM
      - CORE_PEER_BCCSP_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
      - CORE_PEER_BCCSP_PKCS11_PIN=98765432
      - CORE_PEER_BCCSP_PKCS11_LABEL=ForFabric${label}
      - CORE_PEER_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE=/var/hyperledger/production/keystore
      - ORDERER_GENERAL_BCCSP_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
      - ORDERER_GENERAL_BCCSP_PKCS11_PIN=98765432
      - ORDERER_GENERAL_BCCSP_PKCS11_LABEL=ForFabric${label}
      - ORDERER_GENERAL_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE=/var/hyperledger/orderer/keystore
EOM
)
		image=$(cat << EOM
build:
      context: peer-base
      dockerfile: Dockerfile-hsm-peer
EOM
)
	fi	
	
	if [ ${TLS} -ne 0 ]
	then
		privatekey=$(find ${BASEDIR}/crypto-config-tls/peerOrganizations/peerOrg1/peers/peerorg1peer1/keystore -name *_sk)
		tlsvars=$(cat << EOM
      # enabled TLS
      - CORE_PEER_ADDRESSAUTODETECT=true
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config-tls/peerOrganizations/peerOrg1/peers/peerorg1peer1/signcerts/peerorg1peer1-cert.pem
      - CORE_PEER_TLS_KEY_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config-tls/peerOrganizations/peerOrg1/peers/peerorg1peer1/keystore/$(basename ${privatekey})
      - CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config-tls/peerOrganizations/peerOrg1/peers/peerorg1peer1/cacerts/peerOrg1-cert.pem
      # - CORE_PEER_TLS_SERVERHOSTOVERRIDE=peer0
      # The following setting skips the gossip handshake since we are
      # are not doing mutual TLS
      #- CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
      #- CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/peerOrg1/peers/peerOrg1Peer1
    
EOM
)
	else
		tlsvars=$(cat << EOM
      - CORE_PEER_ADDRESSAUTODETECT=true
      - CORE_PEER_TLS_ENABLED=false
EOM
)
	fi	
	
	
	cat >> docker-compose-gen.yaml << EOM
  cli:
    container_name: cli
    $image
    tty: true
    environment:
      - GOPATH=/opt/gopath
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_LOGGING_LEVEL=ERROR
      - CORE_NEXT=true
      - CORE_PEER_ID=cli
      - CORE_PEER_ENDORSER_ENABLED=true
      - CORE_PEER_ADDRESS=peerOrg${org}Peer1:7051
      - CORE_PEER_LOCALMSPID=Org${org}MSP
${tlsvars}
${hsmvars}
      ${CACHERLINK}
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/peer
    command: sleep 600000 #/bin/bash -c './scripts/script.sh ${ORGS} ${PEERNODES} ${CHANNEL_NAME}; '
    volumes:
        - /var/run/:/host/var/run/
        - ./examples/:/opt/gopath/src/github.com/hyperledger/fabric/examples/
        - ./scripts:/opt/gopath/src/github.com/hyperledger/fabric/peer/scripts/
        - ${BASEDIR}/crypto-config:/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config
        - ${BASEDIR}/crypto-config-tls:/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config-tls
        ${hsmvolume}
    depends_on:${DEPENDSON}
EOM
}

function printDockerCompose {
	cat > docker-compose-gen.yaml << EOM
version: '2'

services:
EOM

	if [ ${CACHER} -ne 0 ]
	then
		cat >> docker-compose-gen.yaml << EOM
  apt_proxy:
    container_name: apt_proxy
    build:
      context: peer-base
      dockerfile: Dockerfile-deb-cacher
EOM
		CACHERLINK="- http_proxy=http://apt_proxy:3142"
	fi	

	for ORG in $(seq -f "ordererOrg%g" 1 1)
	do
		for ORDERER in $(seq 1 ${ORDERERNODES})
		do
			printDockerOrderer ${ORDERER} ${ORG}Orderer${ORDERER} ${ORG}
		done
		#initToken ${ORG}Admin
		#initToken ${ORG} #CA
	done
	
	for ORG in $(seq 1 ${ORGS})
	do
		for PEER in $(seq 1 ${PEERNODES})
		do
			printDockerPeer $(expr ${ORG} \* ${ORGS} - ${ORGS} + ${PEER}) ${PEER} ${ORG}
		done
		#for USER in $(seq -f "${ORG}User%g" 1 ${USERNODES})
		#do
		#	initToken ${USER}
		#done
		#initToken ${ORG}Admin
		#initToken ${ORG} #CA
	done
	
	printCliDocker
}

function printConfigTx {
    configtx=configtx.yaml
	cat > ${configtx} << EOM
---
################################################################################
#
#   Profile
#
#   - Different configuration profiles may be encoded here to be specified
#   as parameters to the configtxgen tool
#
################################################################################
Profiles:

    GenOrgsOrdererGenesis:
        Orderer:
            <<: *OrdererDefaults
            Organizations:
EOM
for ORG in $(seq 1 1)
do
	echo "                - *OrdererOrg${ORG}" >> ${configtx}
done

cat >> ${configtx} << EOM
        Consortiums:
            SampleConsortium:
                Organizations:
EOM
for ORG in $(seq 1 ${ORGS})
do
	echo "                    - *Org${ORG}" >> ${configtx}
done
cat >> ${configtx} << EOM
    GenOrgsChannel:
        Consortium: SampleConsortium
        Application:
            <<: *ApplicationDefaults
            Organizations:
EOM

for ORG in $(seq 1 ${ORGS})
do
	echo "                - *Org${ORG}" >> ${configtx}
done

cat >> ${configtx} << EOM
################################################################################
#
#   Section: Organizations
#
#   - This section defines the different organizational identities which will
#   be referenced later in the configuration.
#
################################################################################
Organizations:

    # SampleOrg defines an MSP using the sampleconfig.  It should never be used
    # in production but may be used as a template for other definitions
EOM

for ORG in $(seq 1 1)
do
	cat >> ${configtx} << EOM
    - &OrdererOrg${ORG}
        # DefaultOrg defines the organization which is used in the sampleconfig
        # of the fabric.git development environment
        Name: OrdererOrg${ORG}

        # ID to load the MSP definition as
        ID: OrdererOrg${ORG}MSP

        # MSPDir is the filesystem path which contains the MSP configuration
        MSPDir: ${BASEDIR}/crypto-config/ordererOrganizations/ordererOrg${ORG}/msp
        
        # AdminPrincipal dictates the type of principal used for an organization's Admins policy
        # Today, only the values of Role.ADMIN ad Role.MEMBER are accepted, which indicates a principal
        # of role type ADMIN and role type MEMBER respectively
        AdminPrincipal: Role.MEMBER
EOM
done

for ORG in $(seq 1 ${ORGS})
do
	cat >> ${configtx} << EOM
    - &Org${ORG}
        # DefaultOrg defines the organization which is used in the sampleconfig
        # of the fabric.git development environment
        Name: Org${ORG}MSP

        # ID to load the MSP definition as
        ID: Org${ORG}MSP

        MSPDir: ${BASEDIR}/crypto-config/peerOrganizations/peerOrg${ORG}/msp
        
        # AdminPrincipal dictates the type of principal used for an organization's Admins policy
        # Today, only the values of Role.ADMIN ad Role.MEMBER are accepted, which indicates a principal
        # of role type ADMIN and role type MEMBER respectively
        AdminPrincipal: Role.MEMBER

        AnchorPeers:
            # AnchorPeers defines the location of peers which can be used
            # for cross org gossip communication.  Note, this value is only
            # encoded in the genesis block in the Application section context
            - Host: peerorg${ORG}peer1
              Port: 7051
EOM
done


cat >> ${configtx} << EOM
################################################################################
#
#   SECTION: Orderer
#
#   - This section defines the values to encode into a config transaction or
#   genesis block for orderer related parameters
#
################################################################################
Orderer: &OrdererDefaults

    # Orderer Type: The orderer implementation to start
    # Available types are "solo" and "kafka"
    OrdererType: solo

    Addresses:
        - ordererorg1orderer1:7050

    # Batch Timeout: The amount of time to wait before creating a batch
    BatchTimeout: 2s

    # Batch Size: Controls the number of messages batched into a block
    BatchSize:

        # Max Message Count: The maximum number of messages to permit in a batch
        MaxMessageCount: 10

        # Absolute Max Bytes: The absolute maximum number of bytes allowed for
        # the serialized messages in a batch.
        AbsoluteMaxBytes: 99 MB

        # Preferred Max Bytes: The preferred maximum number of bytes allowed for
        # the serialized messages in a batch. A message larger than the preferred
        # max bytes will result in a batch larger than preferred max bytes.
        PreferredMaxBytes: 512 KB

    Kafka:
        # Brokers: A list of Kafka brokers to which the orderer connects
        # NOTE: Use IP:port notation
        Brokers:
            - 127.0.0.1:9092

    # Organizations is the list of orgs which are defined as participants on
    # the orderer side of the network
    Organizations:

################################################################################
#
#   SECTION: Application
#
#   - This section defines the values to encode into a config transaction or
#   genesis block for application related parameters
#
################################################################################
Application: &ApplicationDefaults

    # Organizations is the list of orgs which are defined as participants on
    # the application side of the network
    Organizations:
EOM
}

function printCryptogenYaml {
	cat > cryptogen.yaml << EOM
PeerOrgs:
EOM
	for ORG in $(seq 1 ${ORGS})
	do
		cat >> cryptogen.yaml << EOM
  - Name: Org${ORG}
    Domain: peerOrg${ORG}
    Users:
      Count: ${USERNODES}
    Specs:
EOM
		for PEER in $(seq 1 ${PEERNODES})
		do
			cat >> cryptogen.yaml << EOM
       - Hostname: peerorg${ORG}peer${PEER} 
         CommonName: peerorg${ORG}peer${PEER} 
EOM
			if [ ${HSM} -ne 0 ]
			then
				cat >> cryptogen.yaml << EOM
         PKCS11:
           Library: ${PKCS11_LIB}
           Label: ${PKCS11_LABEL}peerOrg${ORG}Peer${PEER}
           Pin: ${PKCS11_PIN}
EOM
			fi
		done
		
		if [ ${HSM} -ne 0 ]
		then
			cat >> cryptogen.yaml << EOM
    PKCS11:
       Library: ${PKCS11_LIB}
       Label: ${PKCS11_LABEL} # Prefix
       Pin: ${PKCS11_PIN}
EOM
		fi
	done

	cat >> cryptogen.yaml << EOM

OrdererOrgs:
EOM
	for ORG in $(seq  1 1)
	do
		cat >> cryptogen.yaml << EOM
  - Name: OrdererOrg${ORG}
    Domain: ordererOrg${ORG}
    Specs:
EOM
		for ORDERER in $(seq 1 ${ORDERERNODES})
		do
			cat >> cryptogen.yaml << EOM
       - Hostname: ordererorg${ORG}orderer${ORDERER} 
         CommonName: ordererorg${ORG}orderer${ORDERER} 
EOM
			if [ ${HSM} -ne 0 ]
			then
				cat >> cryptogen.yaml << EOM
         PKCS11:
           Library: ${PKCS11_LIB}
           Label: ${PKCS11_LABEL}ordererOrg${ORG}Orderer${ORDERER}
           Pin: ${PKCS11_PIN}
EOM
			fi
		done
		
		if [ ${HSM} -ne 0 ]
		then
			cat >> cryptogen.yaml << EOM
    PKCS11:
       Library: ${PKCS11_LIB}
       Label: ${PKCS11_LABEL} # Prefix
       Pin: ${PKCS11_PIN}
EOM
        fi
	done
}

#################################################################################
#################################################################################
#################################################################################
#################################################################################


while [[ $# -ge 1 ]]
do
	key="$1"
	
	case $key in
	#directory in which to place artifacts (default ".")
	-baseDir)
		BASEDIR="$2"
		shift
		;;
	
	# number of ordering service nodes (default 1)
	-ordererNodes)
		ORDERERNODES="$2"
		shift
		;;
	
	# number of users per peer organization (default 1)
	-peerOrgUsers)
		USERNODES="$2"
		shift
		;;
		
	# number of unique organizations with peers (default 2)
	-peerOrgs)
		ORGS="$2"
		shift
		;;
		
	# number of peers per organization (default 1)
	-peersPerOrg)
		PEERNODES="$2"
		shift
		;;
	
	-hsm)
		HSM=1
		;;
	
	-tls)
		TLS=1
		;;

	-cacher)
		CACHER=1
		DEPENDSON="
      - apt_proxy"
		;;		
	
	# unknown option
	*)
		echo "Unknown option $key"
		exit 1
		;;
	esac
	shift
done

echo ======== CLEANUP ========
docker rm -f $(docker ps -a -q) || true
docker rmi -f $(docker images | grep dev) || true
rm -rf /var/lib/softhsm/tokens/* ${BASEDIR}/crypto-config ${BASEDIR}/crypto-config-tls configtx.yaml docker-compose-gen.yaml

echo ======== BUILDING CRYPTOGEN ========
go build -o crypto-gen -ldflags -s github.com/hyperledger/fabric/examples/e2e_cli/cryptogen

echo ======== BUILDING CONFIGTXGEN ========
make -C ../.. configtxgen

if [ ${HSM} -ne 0 ]
then
	echo ======== INITIALIZING HSM TOKENS ========
	export PKCS11_LIB=/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so
	export PKCS11_PIN=98765432
	export PKCS11_LABEL=ForFabric #PREFIX
	for ORG in $(seq -f "peerOrg%g" 1 ${ORGS})
	do
		for PEER in $(seq -f "${ORG}Peer%g" 1 ${PEERNODES})
		do
			initToken ${PEER} 
		done
		for USER in $(seq -f "User%g${ORG}" 1 ${USERNODES})
		do
			initToken ${USER}
		done
		initToken Admin${ORG}
		initToken ${ORG} #CA
	done
	
	for ORG in $(seq -f "ordererOrg%g" 1 1)
	do
		for ORDERER in $(seq -f "${ORG}Orderer%g" 1 ${ORDERERNODES})
		do
			initToken ${ORDERER}
		done
		initToken Admin${ORG}
		initToken ${ORG} #CA
	done
fi

echo ======== GENERATING CRYPTOGEN CONFIG ========
printCryptogenYaml

echo ======== GENERATING CRYPTO MATERIAL ========
./crypto-gen generate --output=${BASEDIR}/crypto-config --config=cryptogen.yaml

echo ======== GENERATING TLS CRYPTO MATERIAL ========
HSM=0 printCryptogenYaml
./crypto-gen generate --output=${BASEDIR}/crypto-config-tls --config=cryptogen.yaml

echo ======== COPYING ADMIN- AND CA-CERTS  ========
find crypto-config-tls -name cacerts | while read line
do 
    dest=$(echo $line | sed -e 's/-tls//');
    cert=$(basename $(ls $line/*))
    cp -v $line/$cert $dest/tls-$cert
done
#for ORG in $(seq 1 ${ORGS})
#do
#	cert=${BASEDIR}/crypto-config/peerOrganizations/peerOrg${ORG}/ca/peerOrg${ORG}-cert.pem
#	for TOORG in $(seq 1 ${ORGS})
#	do
#		if [ ${TOORG} -eq ${ORG} ] 
#		then
#			continue
#		fi
#		
#		for PEER in $(seq 1 ${PEERNODES})
#		do
#			cp -v ${cert} ${BASEDIR}/crypto-config/peerOrganizations/peerOrg${TOORG}/peers/peerorg${TOORG}peer${PEER}/admincerts
#			cp -v ${cert} ${BASEDIR}/crypto-config/peerOrganizations/peerOrg${TOORG}/peers/peerorg${TOORG}peer${PEER}/cacerts
#		done
#	done
#done

echo ======== GENERATING CONFIGTX YAML ========
printConfigTx

echo ======== GENERATING GENESIS BLOCK ========
# Help configtxgen find configtx.yaml in current folder
ORIGORDERER_CFG_PATH=$ORDERER_CFG_PATH
export ORDERER_CFG_PATH=${BASEDIR}/crypto-config
../../build/bin/configtxgen -profile GenOrgsOrdererGenesis -outputBlock ${BASEDIR}/crypto-config/ordererOrganizations/ordererOrg1/orderers/ordererorg1orderer1/orderer.block

echo ======== GENERATING CHANNEL CONFIGURATION TRANSACTION ========
../../build/bin/configtxgen -profile GenOrgsChannel -outputCreateChannelTx ${BASEDIR}/crypto-config/channel.tx -channelID mychannel

for ORG in $(seq 1 ${ORGS})
do
	echo ======== GENERATING ANCHOR PEER UPDATE FOR Org${ORG}MSP  ========
	echo ../../build/bin/configtxgen -profile GenOrgsChannel -outputAnchorPeersUpdate ${BASEDIR}/crypto-config/Org${ORG}MSPanchors.tx -channelID mychannel -asOrg Org${ORG}MSP
	../../build/bin/configtxgen -profile GenOrgsChannel -outputAnchorPeersUpdate ${BASEDIR}/crypto-config/Org${ORG}MSPanchors.tx -channelID mychannel -asOrg Org${ORG}MSP
done

export ORDERER_CFG_PATH=$ORIGORDERER_CFG_PATH

echo ======== GENERATING DOCKER COMPOSE ========
printDockerCompose

read -p "Press Enter to start docker compose..."
echo ======== DOCKER COMPOSE START ========
docker-compose -f docker-compose-gen.yaml up
#./network_setup.sh up mychannel

exit
