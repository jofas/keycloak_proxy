get_token() {
  curl -X POST -s -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=password&username=$TEST_USERNAME&password=$TEST_PASSWORD" \
    http://0.0.0.0:$KEYCLOAK_PROXY_PORT/token
}

get_token
