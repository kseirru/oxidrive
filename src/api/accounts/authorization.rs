use std::collections::BTreeMap;
use actix_web::{HttpResponse, Responder, post, web};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::{MySqlPool, Row};
use uuid::Uuid;

#[derive(Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

#[post("/api/accounts/authorization")]
async fn handler(db: web::Data<MySqlPool>, request: web::Json<AuthForm>) -> impl Responder {
    // Checking if user exists \\
    let check_if_exists_query = sqlx::query("SELECT COUNT(*) FROM accounts WHERE username = ?")
        .bind(&request.username)
        .fetch_one(db.get_ref())
        .await
        .unwrap();
    let count: i8 = check_if_exists_query.get(0);

    if count == 0 {
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Account not found!"
        }));
    }

    // Getting password hash and validate it \\
    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
    let password_hash_query = sqlx::query("SELECT password FROM accounts WHERE username = ?")
        .bind(&request.username)
        .fetch_one(db.get_ref())
        .await
        .unwrap();
    let password_hash_str: String = password_hash_query.get(0);

    let password_hash = PasswordHash::new(&password_hash_str).unwrap();
    if argon2
        .verify_password(&request.password.as_bytes(), &password_hash)
        .is_err()
    {
        return HttpResponse::BadRequest().json(json!({
            "error_msg": "Password is incorrect!"
        }));
    }

    // Getting JWT \\ // TODO: Maybe merge both queries into one?
    let getting_uuid_query = sqlx::query("SELECT uuid FROM accounts WHERE username = ?")
        .bind(&request.username)
        .fetch_one(db.get_ref())
        .await
        .unwrap();

    let uuid = Uuid::parse_str(getting_uuid_query.get(0)).unwrap();

    let key: Hmac<Sha256> = Hmac::new_from_slice(dotenv::var("JWT_SECRET").unwrap().as_bytes()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("uuid", uuid.to_string());

    let token = claims.sign_with_key(&key).unwrap();

    // Sending JWT to client \\
    HttpResponse::Ok().json(json!({
        "token": token,
    }))
}
