use std::collections::BTreeMap;
use actix_web::{post, web, HttpResponse, Responder};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::{MySqlPool, Row};
use uuid::Uuid;

#[derive(Deserialize)]
struct RegistrationForm {
    username: String,
    password: String
}

#[post("/api/accounts/registration")]
async fn handler(
    db: web::Data<MySqlPool>,
    request: web::Json<RegistrationForm>,
) -> impl Responder {
    // Checking if user already exists \\
    let check_exists_query = sqlx::query("SELECT COUNT(*) FROM accounts WHERE username=?").bind(&request.username).fetch_one(db.get_ref()).await.unwrap();
    let account_count: i8 = check_exists_query.try_get(0).unwrap();

    if account_count != 0 {
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Account is already exists!"
        }));
    }
    
    
    // Checking length of data \\
    if &request.username.len() > &16 { // TODO: Admin can change this param in config (.env or web-config-panel)
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Username is too long!"
        }));
    }

    if &request.username.len() < &4 { // TODO: Admin can change this param in config (.env or web-config-panel)
        return HttpResponse::BadRequest().json(json!({ 
            "error_msg": "Username is too short!"
        }))
    }
    
    if &request.password.len() > &32 { // TODO: Admin can change this param in config (.env or web-config-panel)
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Password is too long!"
        }));
    }

    if &request.password.len() < &6 { // TODO: Admin can change this param in config (.env or web-config-panel)
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Password is too short!"
        }))
    }
    
    // Generating password hash using Argon2 and UUID \\
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
    
    let password_hash = argon2.hash_password(&request.password.as_bytes(), &salt).unwrap();

    let uuid = Uuid::new_v4();

    // Insert new data into accounts table \\
    sqlx::query("INSERT INTO accounts (uuid, username, password) VALUES (?, ?, ?)")
        .bind(&uuid.to_string())
        .bind(&request.username)
        .bind(&password_hash.to_string())
        .execute(db.get_ref()).await.unwrap();

    // Creating JWT after registration \\
    let key: Hmac<Sha256> = Hmac::new_from_slice(dotenv::var("JWT_SECRET").unwrap().as_bytes()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("uuid", uuid.to_string());

    let token = claims.sign_with_key(&key).unwrap();

    // Sending JWT to client
    HttpResponse::Ok().json(json!({
        "token": token
    }))
}