#![feature(try_trait)]

use actix_web::client::{Client, PayloadError, SendRequestError};
use actix_web::dev::HttpResponseBuilder;
use actix_web::http::StatusCode;
use actix_web::{
  delete, get, post, put, web, HttpRequest, HttpResponse,
};

use actix_oidc_token::{AccessToken, TokenRequest};

use actix_proxy::IntoHttpResponse;

use actix_jwt_validator_middleware::jwks_client::error::Error as JwtError;
use actix_jwt_validator_middleware::jwks_client::keyset::KeyStore;
use actix_jwt_validator_middleware::User as JwtUser;
use actix_jwt_validator_middleware::{init_key_set, jwt_validator};

use serde::{Deserialize, Serialize};

use display_json::DisplayAsJson;

use derive_new::new;

use jonases_tracing_util::tracing::{event, Level};
use jonases_tracing_util::{log_simple_err_callback, logged_var};

use std::env::VarError;
use std::fmt;
use std::option::NoneError;
use std::sync::Arc;

#[derive(Clone)]
pub struct KeycloakProxyApp {
  admin_token: AccessToken,
  key_set: Arc<KeyStore>,
  endpoints: KeycloakEndpoints,
  client_id: ClientId,
  su: SuperUser,
}

#[derive(Debug)]
pub enum InitError {
  VarError,
  KeyStoreInitError,
}

impl From<VarError> for InitError {
  fn from(_: VarError) -> Self {
    Self::VarError
  }
}

impl From<JwtError> for InitError {
  fn from(_: JwtError) -> Self {
    Self::KeyStoreInitError
  }
}

impl KeycloakProxyApp {
  pub async fn init() -> Result<Self, InitError> {
    let client_id =
      ClientId::new(logged_var("KEYCLOAK_PROXY_CLIENT_ID")?);

    let su = SuperUser::new(logged_var("KEYCLOAK_PROXY_SU")?);

    let endpoints = KeycloakEndpoints::new(
      logged_var("KEYCLOAK_PROXY_KEYCLOAK_BASE_URL")?,
      logged_var("KEYCLOAK_PROXY_REALM")?,
    );

    let admin_token = Self::init_admin_token().await?;
    let key_set = init_key_set(&endpoints.certs()).await?;

    Ok(KeycloakProxyApp {
      admin_token,
      key_set,
      endpoints,
      client_id,
      su,
    })
  }

  pub fn config(self) -> impl FnOnce(&mut web::ServiceConfig) {
    move |cfg: &mut web::ServiceConfig| {
      self.build_config(cfg);
    }
  }

  fn build_config(self, cfg: &mut web::ServiceConfig) {
    let needs_auth_scope =
      web::scope("/").wrap(jwt_validator()).service(delete_user);

    cfg
      .data(self.admin_token)
      .data(self.key_set)
      .data(self.endpoints)
      .data(self.client_id)
      .data(self.su)
      .data(Client::builder().disable_timeout().finish())
      .service(certs)
      .service(token)
      .service(register)
      .service(needs_auth_scope);
  }

  async fn init_admin_token() -> Result<AccessToken, VarError> {
    let admin_token_request = TokenRequest::client_credentials(
      "admin-cli".to_owned(),
      logged_var("KEYCLOAK_PROXY_ADMIN_CLI_SECRET")?,
    );

    let admin_token_endpoint = format!(
      "{}/auth/realms/master/protocol/openid-connect/token",
      logged_var("KEYCLOAK_PROXY_KEYCLOAK_BASE_URL")?,
    );

    Ok(
      AccessToken::new(admin_token_endpoint, admin_token_request)
        .periodically_refresh()
        .await,
    )
  }
}

// TODO: to_string() -> inner()
#[derive(Clone, new)]
struct ClientId {
  inner: String,
}

impl fmt::Display for ClientId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[derive(Clone, new)]
struct SuperUser {
  inner: String,
}

impl fmt::Display for SuperUser {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.inner)
  }
}

#[derive(Clone, new)]
struct KeycloakEndpoints {
  keycloak_server: String,
  realm: String,
}

impl KeycloakEndpoints {
  fn certs(&self) -> String {
    format!(
      "{}/auth/realms/{}/protocol/openid-connect/certs",
      self.keycloak_server, self.realm,
    )
  }

  fn token(&self) -> String {
    format!(
      "{}/auth/realms/{}/protocol/openid-connect/token",
      self.keycloak_server, self.realm,
    )
  }

  fn register(&self) -> String {
    format!(
      "{}/auth/admin/realms/{}/users",
      self.keycloak_server, self.realm,
    )
  }

  fn user_query_by_username(&self, username: &str) -> String {
    format!(
      "{}/auth/admin/realms/{}/users?username={}",
      self.keycloak_server, self.realm, username
    )
  }

  fn user(&self, id: &str) -> String {
    format!(
      "{}/auth/admin/realms/{}/users/{}",
      self.keycloak_server, self.realm, id
    )
  }
}

#[derive(Serialize, Deserialize, Debug, DisplayAsJson, new)]
#[serde(rename_all = "camelCase")]
struct User {
  #[new(default)]
  id: Option<String>,
  first_name: String,
  last_name: String,
  email: String,
  enabled: bool,
  username: String,
  #[serde(skip_deserializing)]
  credentials: Vec<Credentials>,
}

impl From<ProxyRegisterRequest> for User {
  fn from(proxy: ProxyRegisterRequest) -> User {
    if let Some(password) = proxy.password {
      User::new(
        proxy.first_name,
        proxy.last_name,
        proxy.email,
        true,
        proxy.username,
        vec![Credentials::password(password)],
      )
    } else {
      User::new(
        proxy.first_name,
        proxy.last_name,
        proxy.email,
        false,
        proxy.username,
        vec![],
      )
    }
  }
}

#[derive(Serialize, Deserialize, Debug, new)]
struct Credentials {
  r#type: String,
  value: String,
}

impl Credentials {
  fn password(password: String) -> Self {
    Self::new("password".to_owned(), password)
  }
}

#[derive(Serialize, Deserialize, Debug, new)]
pub struct ProxyRegisterRequest {
  first_name: String,
  last_name: String,
  username: String,
  email: String,
  password: Option<String>,
}

#[post("/token")]
async fn token(
  request: HttpRequest,
  body: web::Form<TokenRequest>,
  client: web::Data<Client>,
  client_id: web::Data<ClientId>,
  endpoints: web::Data<KeycloakEndpoints>,
) -> Result<HttpResponse, Error> {
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
) -> Result<HttpResponse, Error> {
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
) -> Result<HttpResponse, Error> {
  let registration = User::from(registration_data.into_inner());

  client
    .post(&endpoints.register())
    .header("Content-Type", "application/json")
    .header("Authorization", admin_token.bearer().await?)
    .send_json(&registration)
    .await?
    .into_wrapped_http_response()
}

#[put("/user/{username}/password")]
async fn set_password(
  web::Path((username,)): web::Path<(String,)>,
  client: web::Data<Client>,
  admin_token: web::Data<AccessToken>,
  endpoints: web::Data<KeycloakEndpoints>,
  su: web::Data<SuperUser>,
  jwt_user: JwtUser,
) -> Result<HttpResponse, Error> {
  has_access(&username, &jwt_user, &su.into_inner())?;

  let user = get_user_by_username(
    &username,
    &endpoints,
    &client,
    &admin_token,
  )
  .await?;

  event!(Level::INFO, %user);

  Ok(HttpResponse::Ok().finish())
}

#[delete("/user/{username}")]
async fn delete_user(
  web::Path((username,)): web::Path<(String,)>,
  client: web::Data<Client>,
  admin_token: web::Data<AccessToken>,
  endpoints: web::Data<KeycloakEndpoints>,
  su: web::Data<SuperUser>,
  jwt_user: JwtUser,
) -> Result<HttpResponse, Error> {
  has_access(&username, &jwt_user, &su.into_inner())?;

  let user = get_user_by_username(
    &username,
    &endpoints,
    &client,
    &admin_token,
  )
  .await?;

  event!(Level::INFO, %user);

  client
    .delete(&endpoints.user(&user.id?))
    .header("authorization", admin_token.bearer().await?)
    .send()
    .await
    .map_err(log_simple_err_callback(
      "could not send 'delete user' request",
    ))?
    .into_wrapped_http_response()
}

async fn get_user_by_username(
  username: &str,
  endpoints: &KeycloakEndpoints,
  client: &Client,
  admin_token: &AccessToken,
) -> Result<User, Error> {
  let mut response = client
    .get(&endpoints.user_query_by_username(username))
    .header("Authorization", admin_token.bearer().await?)
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

    let mut users: Vec<User> = serde_json::from_str(&body).map_err(
      log_simple_err_callback(
        "could not parse keycloak response to user object",
      ),
    )?;

    users.pop().ok_or(Error::NotFound)
  } else {
    event!(Level::ERROR, "request returned unsuccessful status code");
    Err(Error::KeycloakError(response.status().as_u16()))
  }
}

fn has_access(
  endpoint: &str,
  user: &JwtUser,
  su: &SuperUser,
) -> Result<(), Error> {
  if endpoint != user.username && user.username != su.to_string() {
    event!(Level::ERROR, "access to endpoint denied");
    Err(Error::AccessDenied)
  } else {
    Ok(())
  }
}

#[derive(Serialize, Debug, DisplayAsJson)]
enum Error {
  SendRequestError,
  PayloadError,
  AccessDenied,
  NoneError,
  NotFound,
  KeycloakError(u16),
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

impl From<NoneError> for Error {
  fn from(_: NoneError) -> Self {
    Self::NoneError
  }
}

impl actix_web::error::ResponseError for Error {
  fn error_response(&self) -> HttpResponse {
    let mut res = HttpResponseBuilder::new(self.status_code());
    res.json(self)
  }

  fn status_code(&self) -> StatusCode {
    match self {
      Self::AccessDenied => StatusCode::FORBIDDEN,
      Self::NotFound => StatusCode::NOT_FOUND,
      Self::KeycloakError(status) => StatusCode::from_u16(*status)
        .map_err(log_simple_err_callback(
          "keycloak provided an invalid status code",
        ))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}
