use actix_web::{App, HttpServer};

use actix_cors::Cors;

use std::env;

use keycloak_proxy::{app_config, init_admin_token};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  let port = env::var("KEYCLOAK_PROXY_PORT").unwrap();
  let addr = format!("0.0.0.0:{}", port);

  let admin_token = init_admin_token().await.unwrap();

  println!("STARTING KEYCLOAK_PROXY SERVER");

  HttpServer::new(move || {
    App::new()
      .data(admin_token.clone())
      .wrap(Cors::permissive()) // TODO: secure
      .configure(app_config)
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
  .run()
  .await
}
