macro_rules! code_response {
    ($code:expr) => {
        Json(json!({ "code": $code })).into_response()
    };
}

use std::{sync::Arc};
use axum::{Extension, Json, extract::State, response::{IntoResponse, Redirect, Response}};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde_json::json;
use sqlx::{Error, MySqlPool};
use crate::types::*;

// TODO
pub async fn project(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar,
    Json(pid): Json<Int>
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn new_project(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn edit_project(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn delete_project(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn project_add_member(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn project_remove_member(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn new_ticket(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn delete_ticket(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn edit_ticket_state(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn assign_user_ticket(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn remove_user_ticket(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}

pub async fn comment_ticket(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    Json(json!({"error": "Not Implemented"}))
}