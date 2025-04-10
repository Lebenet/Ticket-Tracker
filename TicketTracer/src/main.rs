mod types;
mod handlers;
use handlers::{load, account};

use axum::{extract::Extension, routing::{get, post}, Router};
use sqlx::{MySqlPool};
use dotenvy::dotenv;
use std::{env, sync::Arc};
use tower_http::{cors::{Any, CorsLayer}, services::ServeDir};
use types::{SessionStore, new_session_store};

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

    let session_store: SessionStore =  new_session_store();

    // Define Axum routes
    let app = Router::new()
        .route("/", get(load::get_homepage))
        .route("/users", get(load::get_users))
        .route("/login", get(load::get_login_page))
        .route("/login", post(account::login))
        .route("/logout", get(account::logout))
        .route("/register", post(account::register))
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

