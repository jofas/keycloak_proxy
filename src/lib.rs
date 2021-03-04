use actix_web::client::{Client, SendRequestError};
use actix_web::{get, post, web, HttpRequest, HttpResponse};

use actix_oidc_token::{AccessToken, TokenRequest};

use actix_proxy::IntoHttpResponse;

use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;

use std::env;

// TODO: into Env struct
lazy_static! {
  static ref CLIENT_ID: String =
    env::var("KEYCLOAK_PROXY_CLIENT_ID").unwrap();
  static ref ADMIN_CLI_SECRET: String =
    env::var("KEYCLOAK_PROXY_ADMIN_CLI_SECRET").unwrap();
  static ref CERTS_ENDPOINT: String = format!(
    "http://{}:8080/auth/realms/{}/protocol/openid-connect/certs",
    env::var("KEYCLOAK_PROXY_KEYCLOAK_SERVER").unwrap(),
    env::var("KEYCLOAK_PROXY_REALM").unwrap(),
  );
  static ref TOKEN_ENDPOINT: String = format!(
    "http://{}:8080/auth/realms/{}/protocol/openid-connect/token",
    env::var("KEYCLOAK_PROXY_KEYCLOAK_SERVER").unwrap(),
    env::var("KEYCLOAK_PROXY_REALM").unwrap(),
  );
  static ref REGISTER_ENDPOINT: String = format!(
    "http://{}:8080/auth/admin/realms/{}/users",
    env::var("KEYCLOAK_PROXY_KEYCLOAK_SERVER").unwrap(),
    env::var("KEYCLOAK_PROXY_REALM").unwrap(),
  );
  static ref ADMIN_TOKEN_ENDPOINT: String = format!(
    "http://{}:8080/auth/realms/master/protocol/openid-connect/token",
    env::var("KEYCLOAK_PROXY_KEYCLOAK_SERVER").unwrap(),
  );
}

static ADMIN_CLI_CLIENT_ID: &'static str = "admin-cli";

pub fn app_config(cfg: &mut web::ServiceConfig) {
  cfg
    .data(Client::builder().disable_timeout().finish())
    .service(certs)
    .service(token)
    .service(register);
}

pub async fn init_admin_token() -> AccessToken {
  let admin_token_request = TokenRequest::client_credentials(
    ADMIN_CLI_CLIENT_ID.to_owned(),
    ADMIN_CLI_SECRET.clone(),
  );

  AccessToken::new(ADMIN_TOKEN_ENDPOINT.clone(), admin_token_request)
    .periodically_refresh()
    .await
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
  first_name: String,
  last_name: String,
  email: String,
  enabled: bool,
  username: String,
  credentials: Vec<Credentials>,
}

impl From<ProxyRegisterRequest> for RegisterRequest {
  fn from(proxy: ProxyRegisterRequest) -> RegisterRequest {
    RegisterRequest {
      first_name: proxy.first_name,
      last_name: proxy.last_name,
      email: proxy.email,
      enabled: true,
      username: proxy.username,
      credentials: vec![Credentials {
        r#type: String::from("password"),
        value: proxy.password,
      }],
    }
  }
}

#[derive(Serialize, Deserialize, Debug)]
struct Credentials {
  r#type: String,
  value: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyRegisterRequest {
  first_name: String,
  last_name: String,
  username: String,
  email: String,
  password: String,
}

#[post("/token")]
async fn token(
  request: HttpRequest,
  body: web::Form<TokenRequest>,
  client: web::Data<Client>,
) -> Result<HttpResponse, SendRequestError> {
  client
    .request_from(&*TOKEN_ENDPOINT, request.head())
    .send_form(&body.into_inner().add_client_id(CLIENT_ID.clone()))
    .await?
    .into_wrapped_http_response()
}

#[get("/certs")]
async fn certs(
  client: web::Data<Client>,
) -> Result<HttpResponse, SendRequestError> {
  client
    .get(&*CERTS_ENDPOINT)
    .send()
    .await?
    .into_wrapped_http_response()
}

#[post("/register")]
async fn register(
  client: web::Data<Client>,
  admin_token: web::Data<AccessToken>,
  registration_data: web::Json<ProxyRegisterRequest>,
) -> Result<HttpResponse, SendRequestError> {
  let registration =
    RegisterRequest::from(registration_data.into_inner());

  // TODO: no unwraps
  //
  client
    .post(&*REGISTER_ENDPOINT)
    .header("Content-Type", "application/json")
    .header("Authorization", admin_token.bearer().await.unwrap())
    .send_json(&registration)
    .await?
    .into_wrapped_http_response()
}
