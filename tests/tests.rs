use actix_web::{test, App};

use actix_oidc_token::{TokenRequest, TokenResponse};

use futures::stream::TryStreamExt;

use std::env;

use keycloak_proxy::{KeycloakProxyApp, ProxyRegisterRequest};

#[actix_rt::test]
async fn password_request() {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

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

  let token_response: TokenResponse =
    serde_json::from_slice(&bytes).unwrap();

  assert!(token_response.refresh_token.is_some());
}

#[actix_rt::test]
async fn password_request_with_invalid_credentials() {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

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

#[actix_rt::test]
async fn register() {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

  let req_data = ProxyRegisterRequest::new(
    "Test".to_owned(),
    "Test".to_owned(),
    "test_username".to_owned(),
    "test@fassbender.dev".to_owned(),
    "pw".to_owned(),
  );

  let req = test::TestRequest::post()
    .uri("/register")
    .set_json(&req_data)
    .to_request();

  let resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_success());

  let token_request = TokenRequest::password(
    "test@fassbender.dev".to_owned(),
    "pw".to_owned(),
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

  let token_response: TokenResponse =
    serde_json::from_slice(&bytes).unwrap();

  let bearer = format!("Bearer {}", token_response.access_token);

  let req = test::TestRequest::delete()
    .uri("/user/test_username")
    .header("authorization", bearer)
    .to_request();

  let resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_success());
}
