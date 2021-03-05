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

get_admin_token
