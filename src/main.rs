mod api;

use actix_web::{App, HttpServer, web};
use sqlx::mysql::MySqlPoolOptions;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    
    let db = MySqlPoolOptions::new()
        .connect(&format!("mysql://{}:{}@{}/{}",
            dotenv::var("DATABASE_USER").unwrap(),
            dotenv::var("DATABASE_PASSWORD").unwrap(),
            dotenv::var("DATABASE_URL").unwrap(),
            dotenv::var("DATABASE_DATABASE").unwrap(),
        ))
        .await
        .expect("Не удалось подключиться к базе данных");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(api::accounts::registration::handler)
            .service(api::accounts::authorization::handler)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
