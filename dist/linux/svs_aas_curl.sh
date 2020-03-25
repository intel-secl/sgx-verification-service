#!/bin/bash
#Get token from AAS
#to customize, export the correct values before running the script

echo "Setting up SVS Related roles and user in AAS Database"

#Get the value of AAS IP address and port. Default vlue is also provided.
aas_hostname=${AAS_URL:-"https://10.105.167.184:8443"}
CURL_OPTS="-s -k"
IPADDR="10.105.167.184,127.0.0.1,localhost"
CN="SVS TLS Certificate"

mkdir -p /tmp/setup/svs
tmpdir=$(mktemp -d -p /tmp/setup/svs)

cat >$tmpdir/aasAdmin.json <<EOF
{
"username": "admin",
"password": "password"
}
EOF

#Get the JWT Token
curl_output=`curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Accept: application/jwt" --data @$tmpdir/aasAdmin.json -w "%{http_code}" $aas_hostname/aas/token`
echo $curl_output
Bearer_token=`echo $curl_output | rev | cut -c 4- | rev`
response_status=`echo "${curl_output: -3}"`

if rpm -q jq; then
	echo "JQ package installed"
else
	echo "JQ package not installed, please install jq package and try"
	exit 2
fi

#Create svsUser also get user id
create_svs_user() {
cat > $tmpdir/user.json << EOF
{
	"username":"svsuser@svs",
	"password":"svspassword"
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/aas/users > $tmpdir/createsvsuser-response.status

local actual_status=$(cat $tmpdir/createsvsuser-response.status)
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/user_response.json)
	if [ "$response_mesage" = "same user exists" ]; then
		return 2 
	fi
	return 1
fi

if [ -s $tmpdir/user_response.json ]; then
	#jq < $tmpdir/user_response.json
	user_id=$(jq -r '.user_id' < $tmpdir/user_response.json)
	if [ -n "$user_id" ]; then
		echo "Created user id: $user_id"
		SVS_USER_ID=$user_id;
	fi
fi
}

#Add SVS roles
#cms role(svs will create these roles where CN=SVS), getroles(api in aas that is to be map with), keyTransfer, keyCrud
create_user_roles() {

cat > $tmpdir/roles.json << EOF
{
	"service": "$1",
	"name": "$2",
	"context": "$3"
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/roles.json -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/aas/roles > $tmpdir/role_response-status.json

local actual_status=$(cat $tmpdir/role_response-status.json)
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/role_response.json)
	if [ "$response_mesage"="same role exists" ]; then
		return 2 
	fi
	return 1
fi

if [ -s $tmpdir/role_response.json ]; then
	role_id=$(jq -r '.role_id' < $tmpdir/role_response.json)
fi
echo "$role_id"
}

create_roles() {

		local cms_role_id=$( create_user_roles "CMS" "CertApprover" "CN=$CN;SAN=$IPADDR;CERTTYPE=TLS" ) #get roleid
		ROLE_ID_TO_MAP=`echo \"$cms_role_id\"`
		echo $ROLE_ID_TO_MAP
}

#Map svsUser to Roles
mapUser_to_role() {
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles_response.json -w "%{http_code}" $aas_hostname/aas/users/$user_id/roles > $tmpdir/mapRoles_response-status.json

local actual_status=$(cat $tmpdir/mapRoles_response-status.json)
if [ $actual_status -ne 201 ]; then
	return 1 
fi
}

SVS_SETUP_API="create_svs_user create_roles mapUser_to_role"

status=
for api in $SVS_SETUP_API
do
	echo $api
	eval $api
    	status=$?
    if [ $status -ne 0 ]; then
        echo "SVS-AAS User/Role creation failed.: $api"
        break;
    fi
done

if [ $status -eq 0 ]; then
    echo "SVS Setup for AAS-CMS complete: No errors"
fi
if [ $status -eq 2 ]; then
    echo "SVS Setup for AAS-CMS already exists in AAS Database: No action will be done"
fi

#Get Token for SVS USER and configure it is svs config to be used by JAVA Code.
curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Accept: application/jwt" --data @$tmpdir/user.json -o $tmpdir/svs_token-response.json -w "%{http_code}" $aas_hostname/aas/token > $tmpdir/getsvsusertoken-response.status

status=$(cat $tmpdir/getsvsusertoken-response.status)
if [ $status -ne 200 ]; then
	#svs config aas.bearer.token $tmpdir/svs_token-response.json 
	echo "Couldn't get bearer token"
else
	export BEARER_TOKEN=`cat $tmpdir/svs_token-response.json`
	echo $BEARER_TOKEN
fi
