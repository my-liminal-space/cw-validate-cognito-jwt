#!/bin/bash

# Expects to find environment variables for valid cognito username and password:
#   MLS_DDDD_COGNITO_USERNAME
#   MLS_DDDD_COGNITO_PASSWORD

set -e

wrangler publish

MLS_VALID_AWS_JWT="$( aws cognito-idp initiate-auth --client-id 5peen44ratf8dm4hpljvtlhd1m --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME=${MLS_DDDD_COGNITO_USERNAME},PASSWORD=${MLS_DDDD_COGNITO_PASSWORD} --region us-east-1 | jq -r .AuthenticationResult.IdToken )"

echo
echo "${MLS_VALID_AWS_JWT}"
echo

curl "https://mls-cognito-jwt-cw.deaddodgeydigitaldeals.com/?valid_jwt=${MLS_VALID_AWS_JWT}" | jq
echo
