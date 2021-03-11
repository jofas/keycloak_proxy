use actix_web::{test, App};

use actix_oidc_token::{TokenRequest, TokenResponse};

use futures::stream::TryStreamExt;

use jonases_tracing_util::logged_var;

use keycloak_proxy::{KeycloakProxyApp, ProxyRegisterRequest};

#[actix_rt::test]
async fn password_request() {
  jonases_tracing_util::init_logger();

  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

  let token_request = TokenRequest::password(
    logged_var("TEST_USERNAME").unwrap(),
    logged_var("TEST_PASSWORD").unwrap(),
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
  jonases_tracing_util::init_logger();

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

async fn delete_user(username: &str, token: String) -> u16 {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

  let req = test::TestRequest::delete()
    .uri(&format!("/user/{}", username))
    .header("authorization", token)
    .to_request();

  let resp = test::call_service(&mut app, req).await;

  resp.status().as_u16()
}

#[actix_rt::test]
async fn delete_from_self() {
  jonases_tracing_util::init_logger();

  register_user("testuser1", "pw", "test1@fassbender.dev").await;

  let tkn = token("testuser1", "pw").await;

  assert_eq!(delete_user("testuser1", tkn).await, 204);
}

#[actix_rt::test]
async fn delete_from_other() {
  jonases_tracing_util::init_logger();

  register_user("testuser2", "pw", "test2@fassbender.dev").await;

  let tkn = token(
    &logged_var("TEST_USERNAME").unwrap(),
    &logged_var("TEST_PASSWORD").unwrap(),
  )
  .await;

  assert_eq!(delete_user("testuser2", tkn).await, 403);

  let tkn = token("testuser2", "pw").await;

  assert_eq!(delete_user("testuser2", tkn).await, 204);
}

#[actix_rt::test]
async fn delte_from_superuser() {
  jonases_tracing_util::init_logger();

  register_user("testuser3", "pw", "test3@fassbender.dev").await;

  let tkn = token(
    &logged_var("KEYCLOAK_PROXY_SU").unwrap(),
    &logged_var("TEST_SU_PASSWORD").unwrap(),
  )
  .await;

  assert_eq!(delete_user("testuser3", tkn).await, 204);
}

async fn register_user(username: &str, password: &str, email: &str) {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

  let req_data = ProxyRegisterRequest::new(
    "Test".to_owned(),
    "Test".to_owned(),
    username.to_owned(),
    email.to_owned(),
    Some(password.to_owned()),
  );

  let req = test::TestRequest::post()
    .uri("/register")
    .set_json(&req_data)
    .to_request();

  let resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_success());
}

async fn token(username: &str, password: &str) -> String {
  let app = KeycloakProxyApp::init().await.unwrap();

  let mut app =
    test::init_service(App::new().configure(app.config())).await;

  let token_request =
    TokenRequest::password(username.to_owned(), password.to_owned());

  let req = test::TestRequest::post()
    .uri("/token")
    .set_form(&token_request)
    .to_request();

  let mut resp = test::call_service(&mut app, req).await;

  assert!(resp.status().is_success());

  let bytes = test::load_stream(resp.take_body().into_stream())
    .await
    .unwrap();

  let tr: TokenResponse = serde_json::from_slice(&bytes).unwrap();

  format!("Bearer {}", tr.access_token)
}
