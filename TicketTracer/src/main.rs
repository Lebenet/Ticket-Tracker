mod types;
mod handlers;
use handlers::{load, account, projects};

use axum::{extract::Extension, routing::{get, post}, Router};
use axum_server::tls_rustls::RustlsConfig;
use sqlx::{MySqlPool};
use dotenvy::dotenv;
use std::{env, sync::Arc};
use tower_http::{cors::{Any, CorsLayer}, services::{ServeDir, ServeFile}};
use types::{SessionStore, new_session_store};

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    // get DATABASE_URL from .env
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // create a MySQL connection pool
    let pool = Arc::new(MySqlPool::connect(&database_url).await?);
    println!("✅ Connected to MySQL!");
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    //TODO: implement server-side session deletion on cookie expire
    let session_store: SessionStore =  new_session_store();

    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("Failed to install default CryptoProvider");
    // load TLS config
    let config = RustlsConfig::from_pem_file("cert.pem", "key.pem").await?;

    // define Axum routes
    let app = Router::new()
        .route("/", get(load::get_homepage))
        .route("/users", get(load::get_users))
        .route("/login", get(load::get_login_page))
        .route("/login", post(account::login))
        .route("/logout", get(account::logout))
        .route("/register", post(account::register))
        .route("/profile", get(load::get_profile))
        .route("/profile", post(account::profile))
        .route("/change_username", post(account::change_username))
        .route("/reset_password", post(account::reset_password))
        .layer(cors)
        .layer(Extension(session_store))
        .nest_service("/styles.css", ServeFile::new("frontend/styles.css"))
        .nest_service("/js", ServeDir::new("frontend/js"))
        .with_state(pool);

    // start server
    println!("🚀 Server running on https://{}", "0.0.0.0:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("server listen on port : {}", listener.local_addr()?);
    //axum::serve(listener, app).await?;
    axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

