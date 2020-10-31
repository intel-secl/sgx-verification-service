#!/bin/bash

echo "Setting up SGX Verification Related roles and user in AAS Database"

source ~/sqvs.env 2> /dev/null

#Get the value of AAS IP address and port. Default vlue is also provided.
aas_hostname=${AAS_API_URL:-"https://<aas.server.com>:8444/aas"}
CURL_OPTS="-s -k"
CONTENT_TYPE="Content-Type: application/json"
ACCEPT="Accept: application/jwt"
CN="SQVS TLS Certificate"

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

mkdir -p /tmp/setup/sqvs
tmpdir=$(mktemp -d -p /tmp/setup/sqvs)

cat >$tmpdir/aasAdmin.json <<EOF
{
	"username": "admin@aas",
	"password": "aasAdminPass"
}
EOF

#Get the AAS Admin JWT Token
curl_output=`curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/aasAdmin.json -w "%{http_code}" $aas_hostname/token`
Bearer_token=`echo $curl_output | rev | cut -c 4- | rev`

dnf install -qy jq

# This routined checks if sgx Verification service user exists and reurns user id
# it creates a new user if one does not exist
create_sqvs_user()
{
cat > $tmpdir/user.json << EOF
{
	"username":"$SQVS_USERNAME",
	"password":"$SQVS_PASSWORD"
}
EOF

	#check if user already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users?name=$SQVS_USERNAME > $tmpdir/user-response.status

	len=$(jq '. | length' < $tmpdir/user_response.json)
	if [ $len -ne 0 ]; then
		user_id=$(jq -r '.[0] .user_id' < $tmpdir/user_response.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users > $tmpdir/user_response.status

		local status=$(cat $tmpdir/user_response.status)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/user_response.json ]; then
			user_id=$(jq -r '.user_id' < $tmpdir/user_response.json)
			if [ -n "$user_id" ]; then
				echo "${green} Created sqvs user, id: $user_id ${reset}"
			fi
		fi
	fi
}

# This routined checks if sqvs CertApprover role exists and reurns those role ids
# it creates above roles if not present in AAS db
create_roles()
{
cat > $tmpdir/certroles.json << EOF
{
	"service": "CMS",
	"name": "CertApprover",
	"context": "CN=$CN;SAN=$SAN_LIST;CERTTYPE=TLS"
}
EOF

	#check if CertApprover role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles?name=CertApprover > $tmpdir/role_response.status

	cms_role_id=$(jq -r '.[] | select ( .context | contains("SQVS"))' < $tmpdir/role_response.json | jq -r '.role_id')
	if [ -z $cms_role_id ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/certroles.json -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_response-status.json

		local status=$(cat $tmpdir/role_response-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_response.json ]; then
			cms_role_id=$(jq -r '.role_id' < $tmpdir/role_response.json)
		fi
	fi

	ROLE_ID_TO_MAP=`echo \"$cms_role_id\"`
}

#Maps sqvs user to CertApprover Roles
mapUser_to_role()
{
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

	curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles_response.json -w "%{http_code}" $aas_hostname/users/$user_id/roles > $tmpdir/mapRoles_response-status.json

	local status=$(cat $tmpdir/mapRoles_response-status.json)
	if [ $status -ne 201 ]; then
		return 1
	fi
}

SQVS_SETUP_API="create_sqvs_user create_roles mapUser_to_role"
status=
for api in $SQVS_SETUP_API
do
	eval $api
    	status=$?
	if [ $status -ne 0 ]; then
		break;
	fi
done

if [ $status -ne 0 ]; then
	echo "${red} SGX Verification Service user/roles creation failed.: $api ${reset}"
	exit 1
else
	echo "${green} SGX Verification Service user/roles creation succeded ${reset}"
fi

#Get Token for SGX Verification Service user and configure it in sqvs config.
curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/user.json -o $tmpdir/sqvs_token-resp.json -w "%{http_code}" $aas_hostname/token > $tmpdir/get_sqvs_token-response.status

status=$(cat $tmpdir/get_sqvs_token-response.status)
if [ $status -ne 200 ]; then
	echo "${red} Couldn't get bearer token for sqvs user ${reset}"
else
	export BEARER_TOKEN=`cat $tmpdir/sqvs_token-resp.json`
	echo "************************************************************************************************************************************************"
	echo $BEARER_TOKEN
	echo "************************************************************************************************************************************************"
	echo "${green} copy the above token and paste it against BEARER_TOKEN in sqvs.env ${reset}"
fi

# cleanup
rm -rf $tmpdir
