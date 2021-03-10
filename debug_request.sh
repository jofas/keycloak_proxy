get_token() {
  curl -X POST -s -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=password&username=$TEST_USERNAME&password=$TEST_PASSWORD" \
    http://0.0.0.0:$KEYCLOAK_PROXY_PORT/token
}

get_admin_token() {
  REFRESH_TOKEN=$(curl -X POST -s -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=client_credentials&client_id=admin-cli&client_secret=$KEYCLOAK_PROXY_ADMIN_CLI_SECRET" \
    http://0.0.0.0:8080/auth/realms/master/protocol/openid-connect/token \
  | jq .refresh_token)

  curl -X POST -s -H 'content-type:application/x-www-form-urlencoded' \
    -d "grant_type=refresh_token&client_id=admin-cli&refresh_token=${REFRESH_TOKEN//\"}" \
    http://0.0.0.0:8080/auth/realms/master/protocol/openid-connect/token
}

register() {
  curl -X POST -v -H 'content-type: application/json' \
    -d '{
      "first_name": "jonas",
      "last_name": "fassbender",
      "username": "jcool3",
      "email": "jonas3@fc-web.de",
      "password": "supercool"
    }' \
    http://0.0.0.0:$KEYCLOAK_PROXY_PORT/register
}

delete_user() {
  TOKEN=$(get_token jcool3 supercool | jq .access_token)
  echo $TOKEN
  curl -X DELETE -v http://0.0.0.0:$KEYCLOAK_PROXY_PORT/user/jcool3
}

#register
delete_user
#get_admin_token
#get_token $TEST_USERNAME $TEST_PASSWORD
