macro_rules! code_response {
    ($code:expr) => {
        Json(json!({ "code": $code })).into_response()
    };
}

mod types;
use types::*;

use axum::{routing::{get, post}, Router, extract::{State, Extension}, Json, response::{Html, IntoResponse, Response, Redirect}};
use sqlx::{MySqlPool, FromRow, query, Error};
use dotenvy::dotenv;
use std::{sync::Arc, collections::HashMap, env};
use tokio::{fs, sync::Mutex};
use tower_http::{cors::{Any, CorsLayer}, services::ServeDir};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde_json::json;
use cookie as c;
use c::{time::{Duration, OffsetDateTime}};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use rand::Rng;

type SessionStore = Arc<Mutex<HashMap<String, String>>>;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    // Get DATABASE_URL from .env
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create a MySQL connection pool
    let pool = Arc::new(MySqlPool::connect(&database_url).await?);
    println!("✅ Connected to MySQL!");
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let session_store: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    // Define Axum routes
    let app = Router::new()
        .route("/", get(get_homepage))
        .route("/users", get(get_users))
        .route("/login", get(login_page))
        .route("/login", post(login))
        .route("/logout", get(logout))
        .route("/register", post(register))
        .layer(cors)
        .layer(Extension(session_store))
        .fallback_service(ServeDir::new("frontend"))
        .with_state(pool);

    // Start server using hyper::Server
    println!("🚀 Server running on http://{}", "0.0.0.0:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("server listen on port : {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_homepage() -> Html<String> {
    let page = fs::read_to_string("frontend/homepage.html")
        .await
        .unwrap_or_else(|_| { "<h1> Could not load homepage. </h1>".to_string() });

    Html(page)
}

async fn login_page(
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session_id") {
        let session_id = cookie.value().to_string();

        // Check if session ID exists
        let sessions = session_store.lock().await;
        if sessions.contains_key(&session_id) {
            return Redirect::to("/profile").into_response();
        }
    }

    let page = fs::read_to_string("frontend/login.html")
        .await
        .unwrap_or_else(|_| { "<h1> Could not load login page. </h1>".to_string() });

    Html(page).into_response()
}

async fn get_users(State(pool): State<Arc<MySqlPool>>) -> Json<Vec<User>> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&*pool)
        .await
        .unwrap_or_else(|_| vec![]);

    if users.is_empty() {
        println!("Users not found");
    }

    Json(users)
}

async fn login(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    Json(user): Json<LoginRequest>
) -> impl IntoResponse {
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

                let mut cookie = make_cookie(
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

async fn logout(
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

async fn register(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    Json(user): Json<LoginRequest>
) -> impl IntoResponse {
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
            let mut cookie = make_cookie(
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

async fn make_cookie(storage: SessionStore, username: String) -> Cookie<'static> {
    let session_id = generate_session_id().await;
    storage.lock().await.insert(session_id.clone(), username);

    let mut cookie = Cookie::new("session_id", session_id);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::hours(1));

    cookie.into_owned()
}
