macro_rules! code_response {
    ($code:expr) => {
        Json(json!({ "code": $code })).into_response()
    };
}

use std::{sync::Arc};
use axum::{Extension, Json, extract::State, response::{IntoResponse, Redirect}};
use axum_extra::extract::CookieJar;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde_json::json;
use cookie::Cookie;
use rand::Rng;
use sqlx::{Error, MySqlPool};
use time::Duration;
use crate::types::{LoginRequest, User, Codes, SessionStore};

pub async fn login(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    Json(user): Json<LoginRequest>
) -> impl IntoResponse {
    if user.username.is_empty() || user.password.is_empty() {
        return code_response!(Codes::FAIL)
    }

    // Query the database for the user by username
    let row = sqlx::query!(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        user.username
    )
        .fetch_one(&*pool)
        .await;

    match row {
        Ok(row) => {
            // Check if the entered password matches the stored hashed password
            if verify(&user.password, &row.password_hash).unwrap_or(false) {

                let cookie = session_cookie(
                    session_store, user.username.clone()).await;

                let mut response = code_response!(Codes::SUCCESS);
                response.headers_mut().insert(
                    axum::http::header::SET_COOKIE,
                    cookie.to_string().parse().unwrap(),
                );

                response

            } else {
                code_response!(Codes::UNAUTHORIZED)
            }
        }
        Err(Error::RowNotFound) => code_response!(Codes::NOTFOUND),
        Err(_) => code_response!(Codes::FAIL)
    }
}

pub async fn logout(
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar,
) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session_id") {
        // Remove session ID
        let session_id = cookie.value().to_string();
        let mut sessions = session_store.lock().await;
        sessions.remove(&session_id);

        // Clear the credential cookie
        let mut cookie = Cookie::new("session_id", "");
        cookie.set_path("/");
        cookie.set_max_age(Duration::milliseconds(1));
    }

    // Redirect to the login page
    Redirect::to("/login").into_response()
}

pub async fn register(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    Json(user): Json<LoginRequest>
) -> impl IntoResponse {
    if user.username.is_empty() || user.password.is_empty() {
        return code_response!(Codes::FAIL)
    }

    let check = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = ?"
    )
        .bind(&user.username)
        .fetch_optional(&*pool)
        .await
        .unwrap_or_else(|_| None);

    if check.is_some() {
        println!("user found");
        return code_response!(Codes::FOUND);
    }

    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();

    let result = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        user.username,
        hashed_password
    )
        .execute(&*pool)
        .await;

    match result {
        Ok(_) => {
            let cookie = session_cookie(
                session_store, user.username.clone()).await;

            let mut response = code_response!(Codes::SUCCESS);
            response.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                cookie.to_string().parse().unwrap(),
            );

            response
        },
        Err(_) => code_response!(Codes::FAIL)
    }

}

async fn generate_session_id() -> String {
    let mut rng = rand::rng();

    (0..32)  // Length of the session ID
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

async fn session_cookie(storage: SessionStore, username: String) -> Cookie<'static> {
    let session_id = generate_session_id().await;
    storage.lock().await.insert(session_id.clone(), username);

    let mut cookie = Cookie::new("session_id", session_id);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::hours(1));

    cookie.into_owned()
}