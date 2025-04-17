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
        // Homepage
        .route("/", get(load::get_homepage))

        // Login system
        .route("/login", get(load::get_login_page))
        .route("/login", post(account::login))
        .route("/logout", get(account::logout))
        .route("/register", post(account::register))

        // Profile page
        .route("/profile", get(load::get_profile))
        .route("/profile", post(account::profile))
        .route("/change_username", post(account::change_username))
        .route("/reset_password", post(account::reset_password))

        // Projects
        .route("/project", get(load::get_project_page))
        .route("/project", post(projects::project))
        .route("/new_project", post(projects::new_project))
        .route("/edit_project", post(projects::edit_project))
        .route("/delete_project", post(projects::delete_project))
        .route("/project_add_member", post(projects::project_add_member))
        .route("/project_remove_member", post(projects::project_remove_member))

        // Tickets
        .route("/new_ticket", post(projects::new_ticket))
        .route("/delete_ticket", post(projects::delete_ticket))
        .route("/edit_ticket_state", post(projects::edit_ticket_state))
        .route("/assign_user_ticket", post(projects::assign_user_ticket))
        .route("/remove_user_ticket", post(projects::remove_user_ticket))
        .route("/comment_ticket", post(projects::comment_ticket))

        // Extra
        .route("/users", get(load::get_users))

        // Layers
        .layer(cors)
        .layer(Extension(session_store))

        // Redirects
        .nest_service("/styles.css", ServeFile::new("frontend/styles.css"))
        .nest_service("/js", ServeDir::new("frontend/js"))

        // State
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

