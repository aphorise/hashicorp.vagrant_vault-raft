#!/usr/bin/env bash
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands.

if [[ ${1-} ]] && [[ (($# == 1)) || $1 == "-h" || $1 == "--help" || $1 == "help" ]] ; then
printf """Usage: VARIABLE='...' ${0##*/} [OPTIONS]
Installs HashiCorp Vault & setup of services using Beta feature of RAFT Storage.

By default this script only downloads & copies binaries where no inline SETUP
value is provided ('server').

Some of the inline variables and values that can be set are show below.

For upto date & complete documentation of Vault see: https://www.vaultproject.io/

VARIABLES:
		SETUP='' # // default just download binary otherwise 'server'
		VAULT_VERSION='' # // default LATEST - '1.3.2+ent' for enterprise or oss by default.
		IP_WAN_INTERFACE='eth1' # // default for cluster_address uses where not set eth1.

EXAMPLES:
		SETUP='server' ${0##*/} ;
			# install latest vault version setting up systemd services too.

		SETUP='server' IP_WAN_INTERFACE='eth0' ${0##*/} ;
			# Use a differnt interface ip for vault cluster_address binding.

${0##*/} 0.0.1				February 2020
""" ;
fi ;

if ! which curl 2>&1>/dev/null ; then printf 'ERROR: curl utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;
if ! which unzip 2>&1>/dev/null ; then printf 'ERROR: unzip utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;
if ! which jq 2>&1>/dev/null ; then printf 'ERROR: jq utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;

LOGNAME=$(logname) ;

if [[ ! ${SETUP+x} ]]; then SETUP='server' ; fi ; # // default 'server' setup or change to 'client'

if [[ ! ${USER_VAULT+x} ]] ; then USER_VAULT='vault' ; fi ; # // default vault user.

if [[ ! ${URL_VAULT+x} ]]; then URL_VAULT='https://releases.hashicorp.com/vault/' ; fi ;
if [[ ! ${VAULT_VERSION+x} ]]; then VAULT_VERSION='' ; fi ; # // VERSIONS: "1.3.2' for OSS, '1.3.2+ent' for Enterprise, '1.3.2+ent.hsm' for Enterprise with HSM.
if [[ ! ${OS_CPU+x} ]]; then OS_CPU='' ; fi ; # // ARCH CPU's: 'amd64', '386', 'arm64' or 'arm'.
if [[ ! ${OS_VERSION+x} ]]; then OS_VERSION=$(uname -ar) ; fi ; # // OS's: 'Darwin', 'Linux', 'Solaris', 'FreeBSD', 'NetBSD', 'OpenBSD'.

if [[ ! ${PATH_INSTALL+x} ]]; then PATH_INSTALL="$(pwd)/vault_installs" ; fi ; # // where vault install files will be.
if ! mkdir -p ${PATH_INSTALL} 2>/dev/null ; then printf "\nERROR: Could not create directory at: ${PATH_INSTALL}\n"; exit 1; fi ;

if [[ ! ${SYSD_FILE+x} ]]; then SYSD_FILE='/etc/systemd/system/vault.service' ; fi ; # name of SystemD service for vault.
if [[ ! ${PATH_VAULT+x} ]]; then PATH_VAULT='/etc/vault.d' ; fi ; # // Vault Daemon Path where configuration & files are to reside.
if [[ ! ${PATH_BINARY+x} ]]; then PATH_BINARY='/usr/local/bin/vault' ; fi ; # // Target binary location for vault executable.
if [[ ! ${PATH_VAULT_CONFIG+x} ]]; then PATH_VAULT_CONFIG="${PATH_VAULT}/vault.hcl" ; fi ; # // Main vault config.
if [[ ! ${PATH_VAULT_DATA+x} ]]; then PATH_VAULT_DATA='/vault/data' ; fi ; # // Where local storage is used local data path.

if [[ ! ${IP_VAULT_ACTIVE+x} ]]; then IP_VAULT_ACTIVE='192.168.10.252' ; fi ;
if [[ ! ${IP_RAFT_JOIN+x} ]]; then IP_RAFT_JOIN="http://${IP_VAULT_ACTIVE}:8200" ; fi ;

if [[ ! ${IP_WAN_INTERFACE+x} ]]; then IP_WAN_INTERFACE="$(ip a | awk '/: / { print $2 }' | sed -n 3p | cut -d ':' -f1)" ; fi ; # 2nd interface 'eth1'
if [[ ! ${IP_LAN_INTERFACE+x} ]]; then IP_LAN_INTERFACE="$(ip a | awk '/: / { print $2 }' | sed -n 3p | cut -d ':' -f1)" ; fi ; # 2nd interface 'eth1'

if [[ ! ${IP_WAN+x} ]]; then
	IP_WAN="$(ip a show ${IP_WAN_INTERFACE} | grep -oE '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n 1)" ;
	if (( $? != 0 )) ; then printf "ERROR: Unable to determine WAN IP of ${IP_WAN_INTERFACE}\n" ; fi ;
fi ;

if [[ ! ${IP_LAN+x} ]]; then
	IP_LAN="$(ip a show ${IP_LAN_INTERFACE} | grep -oE '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n 1)" ;
	if (( $? != 0 )) ; then printf "ERROR: Unable to determine LAN IP of ${IP_LAN_INTERFACE}\n" ; fi ;
fi ;

VAULT_ADDR="http://${IP_WAN}:8200" ;

if [[ ! ${VAULT_NODENAME+x} ]]; then VAULT_NODENAME=$(hostname) ; fi ; # // will be based on hostname *1 == main, others standby.

# // ----------------------------------------------------------
# // WARNING! DO NOT USE IN REAL LIFE.
# // HACK around / dirty way to get root token from lead node & transite vault node.
function getToken()
{
	if [[ ${VAULT_TOKEN+x} ]] ; then return ; fi ;
	su -l ${LOGNAME} -c "printf \"$(ssh-keyscan -H ${IP_TRANSIT} 2>/dev/null)\" >> ~/.ssh/known_hosts" ;
	su -l ${LOGNAME} -c "scp ${IP_TRANSIT}:~/vinit.txt vault_node1_vinit.txt" ;

	if ! [[ ${VAULT_NODENAME} == *"2" ]] ; then
		su -l ${LOGNAME} -c "printf \"$(ssh-keyscan -H ${IP_VAULT_ACTIVE} 2>/dev/null)\" >> ~/.ssh/known_hosts" ;
		su -l ${LOGNAME} -c "scp ${IP_VAULT_ACTIVE}:~/vinit.txt vault_node2_vinit.txt" ;
		export VAULT_TOKEN=$(su -l ${LOGNAME} -c "cat vault_node2_vinit.txt | jq -r .root_token") ;
	fi ;
	printf 'COPIED: vinit.txt files from nodes 1&2\n' ;
	export TRANSIT_TOKEN=$(su -l ${LOGNAME} -c "cat vault_node1_vinit.txt | jq -r .root_token") ;
}
if ! [[ ${VAULT_NODENAME} == *"1" ]] ; then getToken ; fi ;
# // ----------------------------------------------------------

if [[ ! ${VAULT_CONFIG_SETTINGS+x} ]]; then VAULT_CONFIG_SETTINGS='' ; fi ; # // vault config settings.

if [[ ${VAULT_CONFIG_SETTINGS} == '' ]] ; then
	VAULT_CONFIG_SETTINGS='listener "tcp" {
	address		= "0.0.0.0:8200"
#	tls_cert_file	= "/home/vagrant/vault_certificate.pem"
#	tls_key_file	= "/home/vagrant/vault_privatekey.pem"
	cluster_address	= "'${IP_WAN}':8201"
	tls_disable		= "true"
}

api_addr = "http://'${IP_WAN}':8200"
cluster_addr = "https://'${IP_WAN}':8201"
ui = true
' ;
	# // first node (by IP in cluter) gets in mem all other raft path.
	if [[ ${VAULT_NODENAME} == *"1" ]]	; then
		VAULT_CONFIG_SETTINGS+='
# // ---------------------------------------------------
# // PRIMARY NODE GETS:
storage "inmem" {}
# // ---------------------------------------------------
' ;
	else
		if [[ ! ${TRANSIT_TOKEN+x} ]] ; then
			export sTRANSIT_TOKEN='\t#token				= ""' ;
		else
			export sTRANSIT_TOKEN="\ttoken				= \"${TRANSIT_TOKEN}\"	# read from VAULT_TOKEN env" ;
		fi ;

		if [[ ! ${IP_TRANSIT+x} ]] ; then
			export sIP_TRANSIT='\t# address				= "http://...:8200"' ;
		else
			export sIP_TRANSIT="\taddress				= \"http://${IP_TRANSIT}:8200\"" ;
		fi ;

		VAULT_CONFIG_SETTINGS+='
# // ---------------------------------------------------
# // SECONDARY NODES:
storage "raft" {
	path		= "'${PATH_VAULT_DATA}'"
#	node_id		= "'${VAULT_NODENAME}'"
}

seal "transit" {
'${sIP_TRANSIT}'
'${sTRANSIT_TOKEN}'
	disable_renewal		= "false"
	# // Key configuration
	key_name			= "unseal_key"
	mount_path			= "transit/"
}
disable_mlock = true
# // ---------------------------------------------------
' ;
	fi ;
fi ;

sERR="\nREFER TO: ${URL_VAULT}\n\nERROR: Operating System Not Supported.\n" ;
sERR_DL="\nREFER TO: ${URL_VAULT}\n\nERROR: Could not determined download state.\n" ;

# // PGP Public Key on Security Page which can be piped to file.
#PGP_KEY_PUB=$(curl -s https://www.hashicorp.com/security.html | grep -Pzo '\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-\n.*\n(\n.*){27}?') ;
#curl -s ${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS.sig ;
#getconf LONG_BIT ; # // can be handy for 32bit vs 64bit determination

# // DETERMINE LATEST VERSION - where none are provided.
if [[ ${VAULT_VERSION} == '' ]] ; then
	VAULT_VERSION=$(curl -s ${URL_VAULT} | grep '<a href="/vault/' | grep -v -E 'rc|ent|beta|hsm' | head -n 1 | grep -E -o '([0-9]{1,3}[\.]){2}[0-9]{1,3}' | head -n 1) ;
	if [[ ${VAULT_VERSION} == '' ]] ; then
		printf '\nERROR: Could not determine valid / current vault version to download.\n' ;
		exit 1 ;
	fi ;
fi ;

if [[ ! ${FILE+x} ]] ; then FILE="vault_${VAULT_VERSION}_" ; fi ; # // to be appended later.
if [[ ! ${URL+x} ]] ; then URL="${URL_VAULT}${VAULT_VERSION}/" ; fi ; # // to be appended later.
if [[ ! ${URL2+x} ]] ; then URL2="${URL_VAULT}${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" ; fi ;

set +e ; CHECK=$(vault --version 2>&1) ; set -e ; # // maybe required vault version is already installed.
if [[ ${CHECK} == *"v${VAULT_VERSION}"* ]] && [[ (($# == 0)) || $1 != "-f" || $2 != "-f" ]] ; then printf "Vault v${VAULT_VERSION} already installed; Use '-f' to force this script to run anyway.\nNo action taken.\n" && exit 0 ; fi ;

sAOK="Remember to copy ('cp'), link ('ln') or path the vault executable as required.\n" ;
sAOK+="Try: '${PATH_BINARY} --version' ; # to test.\nSuccessfully installed Vault ${VAULT_VERSION} in: ${PATH_INSTALL}\n" ;

function donwloadUnpack()
{
	printf "Downloading from: ${URL}\n" ;
	cd ${PATH_INSTALL} && \
	if wget -qc ${URL} && wget -qc ${URL2} ; then
		if [[ $(shasum -a 256 -c vault_${VAULT_VERSION}_SHA256SUMS 2>&1>/dev/null | grep OK) == "" ]] ; then
			if unzip -qo ${FILE} ; then printf "${sAOK}" ; else printf "\nERROR: Could not unzip.\n" ; exit 1 ; fi ;
			chown -R ${LOGNAME} ${PATH_INSTALL} ;
		else
			printf '\nERROR: During shasum - Downloaded .zip corrupted?\n' ;
			exit 1 ;
		fi ;
	else
		printf "${sERR_DL}" ;
	fi ;
}

if [[ ${OS_CPU} == '' ]] ; then
	if [[ ${OS_VERSION} == *'x86_64'* ]] ; then
		OS_CPU='amd64' ;
	else
		if [[ ${OS_VERSION} == *' i386'* || ${OS_VERSION} == *' i686'* ]] ; then OS_CPU='386' ; fi ;
		if [[ ${OS_VERSION} == *' armv6'* || ${OS_VERSION} == *' armv7'* ]] ; then OS_CPU='arm' ; fi ;
		if [[ ${OS_VERSION} == *' armv8'* || ${OS_VERSION} == *' aarch64'* ]] ; then OS_CPU='arm64' ; fi ;
		if [[ ${OS_VERSION} == *'solaris'* ]] ; then OS_CPU='amd64' ; fi ;
	fi ;
	if [[ ${OS_CPU} == '' ]] ; then printf "${sERR}" ; exit 1 ; fi ;
fi ;

case "$(uname -ar)" in
	Darwin*)
		printf 'macOS (aka OSX)\n' ;
		if which brew > /dev/null ; then
			printf 'Consider: "brew install vault" since you have HomeBrew availble.\n' ;
		else :; fi ;
		FILE="${FILE}darwin_${OS_CPU}.zip" ;
	;;
	Linux*)
		printf 'Linux\n' ;
		FILE="${FILE}linux_${OS_CPU}.zip" ;
	;;
	*Solaris)
		printf 'SunOS / Solaris\n' ;
		FILE="${FILE}solaris_${OS_CPU}.zip" ;
	;;
	*FreeBSD*)
		printf 'FreeBSD\n' ;
		FILE="${FILE}freebsd_${OS_CPU}.zip" ;
	;;
	*NetBSD*)
		printf 'NetBSD\n' ;
		FILE="${FILE}netbsd_${OS_CPU}.zip" ;
	;;
	*OpenBSD*)
		printf 'OpenBSD\n' ;
		FILE="${FILE}netbsd_${OS_CPU}.zip" ;
	;;
	*Cygwin)
		printf 'Cygwin - POSIX on MS Windows\n'
		FILE="${FILE}windows_${OS_CPU}.zip" ;
		URL="${URL}${FILE}" ;
		printf "Conisder downloading (exe) from: ${URL}.\nUse vault.exe from CMD / Windows Prompt(s).\n" ;
		exit 0 ;
	;;
	*)
		printf "${sERR}" ;
		exit 1 ;
	;;
esac ;


function sudoSetup()
{
	if [[ ${FILE} == *"darwin"* ]] ; then printf '\nWARNING: On MacOS - all other setup setps will need to be appropriatly completed by the user.\n' ; exit 0 ; fi ;
	if ! [[ $(id -u) == 0 ]] ; then printf 'ERROR: Root privileges lacking to peform all setup tasks. Consider "sudo ..." re-execution.\n' ; exit 1 ; fi ;

	# // Move vault to default paths
	cd ${PATH_INSTALL} && \
	chown root:root vault && \
	mv vault ${PATH_BINARY} ;

	# Give ability to mlock syscall without running the process as root & preventing memory from being swapped to disk.
	setcap cap_ipc_lock=+ep ${PATH_BINARY} ; # // /usr/local/bin/vault

	# Create a unique, non-privileged system user to run Vault.
	if ! id -u ${USER_VAULT} &>/dev/null ; then
		useradd --system --home ${PATH_VAULT} --shell /bin/false ${USER_VAULT} ;
	else
		printf 'USER: vault - already present.\n' ;
	fi ;

	# // Enable auto complete
	set +e
	vault -autocomplete-install 2>/dev/null && complete -C ${PATH_BINARY} vault 2>/dev/null;
	USER=$(logname) ;
	su -l ${USER} -c "vault -autocomplete-install 2>/dev/null && complete -C ${PATH_BINARY} vault 2>/dev/null;"
	set -e

	# // SystemD for service / startup
	if ! which systemctl 2>&1>/dev/null ; then printf '\nERROR: No systemctl / SystemD installed on system.' ; exit 1 ; fi ;
	if [[ ${FILE} == *"darwin"* ]] ; then printf '\nERROR: Only SystemD can be provisioned - build MacOS launchd plist yourself.\n' ; exit 1 ; fi ;

	if ! [[ -d ${PATH_VAULT_DATA} ]] ; then mkdir -p ${PATH_VAULT_DATA} && chown -R ${USER_VAULT}:${USER_VAULT} ${PATH_VAULT_DATA} ; fi ;

	if mkdir -p ${PATH_VAULT} && touch ${PATH_VAULT_CONFIG} && chown -R ${USER_VAULT}:${USER_VAULT} ${PATH_VAULT} && chmod 640 ${PATH_VAULT_CONFIG} ; then
		if ! [[ -s ${PATH_VAULT_CONFIG} ]] ; then
			printf "${VAULT_CONFIG_SETTINGS}" >> ${PATH_VAULT_CONFIG} ;
		else
			printf "VAULT Conifg: ${PATH_VAULT_CONFIG} - already present.\n" ;
		fi ;
	else
		printf "\nERROR: Unable to create ${PATH_VAULT}.\n" ; exit 1 ;
	fi ;

	if ! [[ -s ${SYSD_FILE} ]] && [[ ${SETUP,,} == *'server'* ]]; then
		UNIT_SYSTEMD='[Unit]\nDescription="HashiCorp Vault - A tool for managing secrets"\nDocumentation=https://www.vaultproject.io/docs/\nRequires=network-online.target\nAfter=network-online.target\nConditionFileNotEmpty=/etc/vault.d/vault.hcl\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nUser=vault\nGroup=vault\nProtectSystem=full\nProtectHome=read-only\nPrivateTmp=yes\nPrivateDevices=yes\nSecureBits=keep-caps\nAmbientCapabilities=CAP_IPC_LOCK\nCapabilities=CAP_IPC_LOCK+ep\nCapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK\nNoNewPrivileges=yes\nExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl\nExecReload=/bin/kill --signal HUP $MAINPID\nKillMode=process\nKillSignal=SIGINT\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nStartLimitInterval=60\nStartLimitIntervalSec=60\nStartLimitBurst=3\nLimitNOFILE=65536\nLimitMEMLOCK=infinity\n\n[Install]\nWantedBy=multi-user.target\n' ;
		printf "${UNIT_SYSTEMD}" > ${SYSD_FILE} && chmod 664 ${SYSD_FILE} ;
		systemctl daemon-reload ;
		systemctl enable vault.service ;
		systemctl start vault.service ;
	fi ;
}


function setupRAFT()
{
	TIME_PAUSE=3 ; # // pause to allow for daemon to start.
	# // hostname ending in 1 is in mem server
	if [[ ${VAULT_NODENAME} == *"1" || ${VAULT_NODENAME} == *"2" ]] && [[ ${SETUP,,} == *"server"* ]] ; then
		sleep ${TIME_PAUSE} ;
		VAULT_IK_PATH="/home/${LOGNAME}/vinit.txt" ;
		INIT_RESPONSE=$(VAULT_ADDR=${VAULT_ADDR} vault operator init -format=json -key-shares 1 -key-threshold 1) ;
		printf "${INIT_RESPONSE}" > ${VAULT_IK_PATH} && chown ${LOGNAME}:${LOGNAME} ${VAULT_IK_PATH} ;
		if [[ ${VAULT_NODENAME} == *"1" ]] ; then
			UNSEAL_KEY=$(printf "${INIT_RESPONSE}" | jq -r .unseal_keys_b64[0]) ;
		fi ;

		if [[ ${VAULT_NODENAME} == *"2" ]] ; then
			UNSEAL_KEY=$(printf "${INIT_RESPONSE}" | jq -r .recovery_keys_b64[0]) ;
		fi ;

		VAULT_TOKEN=$(printf "${INIT_RESPONSE}" | jq -r .root_token) ;

		## // actually unseal
		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault operator unseal ${UNSEAL_KEY} 2>&1 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: Unsealed ${VAULT_NODENAME}.\n" ; fi ;
	fi ;

	if ! grep VAULT_TOKEN /home/${LOGNAME}/.bashrc ; then
		printf "\nexport VAULT_TOKEN=${VAULT_TOKEN}\n" >> /home/${LOGNAME}/.bashrc ;
	fi ;

	if ! grep VAULT_ADDR /home/${LOGNAME}/.bashrc ; then
		printf "\nexport VAULT_ADDR=${VAULT_ADDR}\n" >> /home/${LOGNAME}/.bashrc ;
		printf "REMEMBER to: \`source ~/.bashrc ; # // or you'll need: VAULT_ADDR='${VAULT_ADDR}' vault ...\`\n" ;
	fi ;

	if ! grep VAULT_ADDR ~/.bashrc ; then printf "\nexport VAULT_ADDR=${VAULT_ADDR}\n" >> ~/.bashrc ; fi ;

	# // on node1 we need transit on with unseal_key
	if [[ ${VAULT_NODENAME} == *"1" ]] ; then
		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault secrets enable transit > 1 > 2 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: ENABLED Transit Engine on ${VAULT_NODENAME}.\n" ; fi ;
		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault write -f transit/keys/unseal_key > 1 > 2 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: Wrote transit/keys/unseal_key on ${VAULT_NODENAME}.\n" ; fi ;
	fi ;

	# // on node2 we'll enable kv store & do a wrte.
	if [[ ${VAULT_NODENAME} == *"2" ]] ; then
		sleep ${TIME_PAUSE} ; # // need to wait 9 or more secs.
		sleep ${TIME_PAUSE} ; # // need to wait 9 or more secs.
		sleep ${TIME_PAUSE} ; # // need to wait 9 or more secs.
		sleep ${TIME_PAUSE} ; # // need to wait 9 or more secs.

		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault secrets enable -path=kv kv-v2 > 1 > 2 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: ENABLED KV2 store on ${VAULT_NODENAME}.\n" ; fi ;
		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault kv put kv/apikey webapp=ABB39KKPTWOR832JGNLS02 > 1 > 2 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: Wrote kv/apikey on ${VAULT_NODENAME}.\n" ; fi ;
	fi ;

	if ! [[ ${VAULT_NODENAME} == *"1" || ${VAULT_NODENAME} == *"2" ]] && [[ ${SETUP,,} == *"server"* ]] ; then
		sleep ${TIME_PAUSE} ;
		VAULT_TOKEN="${VAULT_TOKEN}" VAULT_ADDR=${VAULT_ADDR} vault operator raft join ${IP_RAFT_JOIN} > 1 > 2 > /dev/null ;
		if (($? == 0)) ; then printf "SUCCESSFULLY: RAFT JOINED ${VAULT_NODENAME} to ${IP_RAFT_JOIN}.\n" ; fi ;
	fi ;
}

URL="${URL}${FILE}" ;
donwloadUnpack && if [[ ${SETUP,,} == *"server"* ]]; then sudoSetup && setupRAFT ; fi ;
