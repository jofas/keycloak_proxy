use actix_web::client::{Client, PayloadError, SendRequestError};
use actix_web::dev::HttpResponseBuilder;
use actix_web::http::StatusCode;
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};

use actix_oidc_token::{AccessToken, TokenRequest};

use actix_proxy::IntoHttpResponse;

use serde::{Deserialize, Serialize};

use display_json::DisplayAsJson;

use derive_new::new;

use jonases_tracing_util::tracing::{event, Level};
use jonases_tracing_util::{log_simple_err_callback, logged_var};

use std::env::VarError;
use std::fmt;

#[derive(new)]
struct ClientId {
  inner: String,
}

impl fmt::Display for ClientId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[derive(new)]
struct KeycloakEndpoints {
  keycloak_server: String,
  realm: String,
}

impl KeycloakEndpoints {
  fn certs(&self) -> String {
    format!(
      "http://{}:8080/auth/realms/{}/protocol/openid-connect/certs",
      self.keycloak_server, self.realm,
    )
  }

  fn token(&self) -> String {
    format!(
      "http://{}:8080/auth/realms/{}/protocol/openid-connect/token",
      self.keycloak_server, self.realm,
    )
  }

  fn register(&self) -> String {
    format!(
      "http://{}:8080/auth/admin/realms/{}/users",
      self.keycloak_server, self.realm,
    )
  }

  fn user_query_by_username(&self, username: &str) -> String {
    format!(
      "http://{}:8080/auth/admin/realms/{}/users?username={}",
      self.keycloak_server, self.realm, username
    )
  }

  fn user(&self, id: &str) -> String {
    format!(
      "http://{}:8080/auth/admin/realms/{}/users/{}",
      self.keycloak_server, self.realm, id
    )
  }
}

pub fn app_config(cfg: &mut web::ServiceConfig) {
  let client_id =
    ClientId::new(logged_var("KEYCLOAK_PROXY_CLIENT_ID").unwrap());

  let endpoints = KeycloakEndpoints::new(
    logged_var("KEYCLOAK_PROXY_KEYCLOAK_SERVER").unwrap(),
    logged_var("KEYCLOAK_PROXY_REALM").unwrap(),
  );

  cfg
    .data(client_id)
    .data(endpoints)
    .data(Client::builder().disable_timeout().finish())
    .service(certs)
    .service(token)
    .service(register)
    .service(delete_user);
}

pub async fn init_admin_token() -> Result<AccessToken, VarError> {
  let admin_token_request = TokenRequest::client_credentials(
    "admin-cli".to_owned(),
    logged_var("KEYCLOAK_PROXY_ADMIN_CLI_SECRET")?,
  );

  let admin_token_endpoint = format!(
    "http://{}:8080/auth/realms/master/protocol/openid-connect/token",
    logged_var("KEYCLOAK_PROXY_KEYCLOAK_SERVER")?,
  );

  Ok(
    AccessToken::new(admin_token_endpoint, admin_token_request)
      .periodically_refresh()
      .await,
  )
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
  client_id: web::Data<ClientId>,
  endpoints: web::Data<KeycloakEndpoints>,
) -> Result<HttpResponse, SendRequestError> {
  client
    .request_from(&endpoints.token(), request.head())
    .send_form(
      &body.into_inner().add_client_id(client_id.to_string()),
    )
    .await?
    .into_wrapped_http_response()
}

#[get("/certs")]
async fn certs(
  client: web::Data<Client>,
  endpoints: web::Data<KeycloakEndpoints>,
) -> Result<HttpResponse, SendRequestError> {
  client
    .get(&endpoints.certs())
    .send()
    .await?
    .into_wrapped_http_response()
}

#[post("/register")]
async fn register(
  client: web::Data<Client>,
  admin_token: web::Data<AccessToken>,
  registration_data: web::Json<ProxyRegisterRequest>,
  endpoints: web::Data<KeycloakEndpoints>,
) -> Result<HttpResponse, SendRequestError> {
  let registration =
    RegisterRequest::from(registration_data.into_inner());

  // TODO: no unwraps
  //
  client
    .post(&endpoints.register())
    .header("Content-Type", "application/json")
    .header("Authorization", admin_token.bearer().await.unwrap())
    .send_json(&registration)
    .await?
    .into_wrapped_http_response()
}

#[derive(Serialize, Deserialize, Clone, DisplayAsJson)]
#[serde(rename_all(deserialize = "camelCase"))]
struct User {
  id: String,
  username: String,
  first_name: String,
  last_name: String,
  email: String,
}

#[delete("/user/{username}")]
async fn delete_user(
  web::Path((username,)): web::Path<(String,)>,
  client: web::Data<Client>,
  admin_token: web::Data<AccessToken>,
  endpoints: web::Data<KeycloakEndpoints>,
) -> Result<HttpResponse, Error> {
  let mut response = client
    .get(&endpoints.user_query_by_username(&username))
    .header("Authorization", admin_token.bearer().await.unwrap())
    .send()
    .await
    .map_err(log_simple_err_callback(
      "could not query keycloak server",
    ))?;

  if response.status().is_success() {
    let body =
      response.body().await.map_err(log_simple_err_callback(
        "retrieving payload from request resulted in an error",
      ))?;

    let body = String::from_utf8_lossy(&*body);

    event!(Level::DEBUG, raw_user = %body);

    let users: Vec<User> = serde_json::from_str(&body).map_err(
      log_simple_err_callback(
        "could not parse keycloak response to user object",
      ),
    )?;

    if users.len() == 0 {
      return Ok(HttpResponse::NotFound().finish());
    }

    let user = users[0].clone();

    event!(Level::INFO, %user);

    client
      .delete(&endpoints.user(&user.id))
      .header("Authorization", admin_token.bearer().await.unwrap())
      .send()
      .await
      .map_err(log_simple_err_callback(
        "could not send 'delete user' request",
      ))?
      .into_wrapped_http_response()
  } else {
    event!(Level::ERROR, "request returned unsuccessful status code");
    Ok(HttpResponse::InternalServerError().finish())
  }
}

#[derive(Serialize, Debug)]
enum Error {
  SendRequestError,
  PayloadError,
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

impl From<SendRequestError> for Error {
  fn from(_: SendRequestError) -> Self {
    Self::SendRequestError
  }
}

impl From<PayloadError> for Error {
  fn from(_: PayloadError) -> Self {
    Self::PayloadError
  }
}

impl From<serde_json::Error> for Error {
  fn from(_: serde_json::Error) -> Self {
    Self::PayloadError
  }
}

impl actix_web::error::ResponseError for Error {
  fn error_response(&self) -> HttpResponse {
    let mut res = HttpResponseBuilder::new(self.status_code());
    res.json(self)
  }

  fn status_code(&self) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
  }
}
