use actix_web::{App, HttpServer};

use actix_cors::Cors;

use jonases_tracing_util::tracing::{event, Level};
use jonases_tracing_util::{init_logger, logged_var};

use keycloak_proxy::KeycloakProxyApp;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  init_logger();

  let port = logged_var("KEYCLOAK_PROXY_PORT").unwrap();
  let addr = format!("0.0.0.0:{}", port);

  let app = KeycloakProxyApp::init().await.unwrap();

  event!(Level::INFO, "STARTING KEYCLOAK_PROXY SERVER");

  HttpServer::new(move || {
    App::new()
      .wrap(Cors::permissive()) // TODO: secure
      .configure(app.clone().config())
    /*
    .wrap_fn(|req, srv| {
      println!("{:?}", req);
      srv.call(req).map(|res| {
        println!("{:?}", res);
        res
      })
    })
    */
  })
  .bind(&addr)?
  .client_timeout(0)
  .run()
  .await
}
