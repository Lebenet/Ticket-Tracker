use std::sync::Arc;
use axum::{Extension, Json};
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::CookieJar;
use sqlx::MySqlPool;
use tokio::fs;
use crate::SessionStore;
use crate::types::User;

pub async fn get_homepage() -> Html<String> {
    let page = fs::read_to_string("frontend/homepage.html")
        .await
        .unwrap_or_else(|_| { "<h1> Could not load homepage. </h1>".to_string() });

    Html(page)
}

pub async fn get_profile(
    cookies: CookieJar
) -> impl IntoResponse {
    if let Some(_) = cookies.get("session_id") {
        let page: String = fs::read_to_string("frontend/profile.html")
            .await
            .unwrap_or_else(|_| { "<h1> Could not load profile. </h1>".to_string() });

        Html(page).into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

pub async fn get_login_page(
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

pub async fn get_users(State(pool): State<Arc<MySqlPool>>) -> Json<Vec<User>> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&*pool)
        .await
        .unwrap_or_else(|_| vec![]);

    if users.is_empty() {
        println!("Users not found");
    }

    Json(users)
}
pub async fn get_project_page(
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session_id") {
        let session_id = cookie.value().to_string();

        // Check if session ID exists
        let sessions = session_store.lock().await;
        if !sessions.contains_key(&session_id) {
            Redirect::to("/login").into_response()
        } else {

            let page = fs::read_to_string("frontend/project.html")
                .await
                .unwrap_or_else(|_| { "<h1> Could not load project page. </h1>".to_string() });

            Html(page).into_response()
        }
    } else {
        Redirect::to("/login").into_response()
    }
}