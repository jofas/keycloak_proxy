use actix_web::{test, App};

use actix_oidc_token::{TokenRequest, TokenResponse};

use futures::stream::TryStreamExt;

use std::env;

use keycloak_proxy::{app_config, init_admin_token};

#[actix_rt::test]
async fn password_request() {
  let admin_token = init_admin_token().await;
  let mut app = test::init_service(
    App::new().configure(app_config).data(admin_token),
  )
  .await;

  let token_request = TokenRequest::password(
    env::var("TEST_USERNAME").unwrap(),
    env::var("TEST_PASSWORD").unwrap(),
  );

  let req = test::TestRequest::post()
    .uri("/token")
    .set_form(&token_request)
    .to_request();

  let mut resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_success());

  let bytes = test::load_stream(resp.take_body().into_stream())
    .await
    .unwrap();

  let _token_response: TokenResponse =
    serde_json::from_slice(&bytes).unwrap();
}

#[actix_rt::test]
async fn password_request_with_invalid_credentials() {
  let admin_token = init_admin_token().await;
  let mut app = test::init_service(
    App::new().configure(app_config).data(admin_token),
  )
  .await;

  let token_request = TokenRequest::password(
    "not a user".to_owned(),
    "not a password".to_owned(),
  );

  let req = test::TestRequest::post()
    .uri("/token")
    .set_form(&token_request)
    .to_request();

  let resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_client_error());
}
