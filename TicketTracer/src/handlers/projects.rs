macro_rules! code_response {
    ($code:expr, $message:expr) => {
        Json(json!({ "code": $code, "message": $message })).into_response()
    };
}


use std::{sync::Arc};
use axum::{Extension, Json, extract::State, response::{IntoResponse, Redirect, Response}};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde_json::json;
use sqlx::{Error, MySqlPool};
use time::Duration;
use crate::types::*;

use crate::handlers::cust::*;

// TODO
pub async fn project(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    let response = check_session(State(pool.clone()), Extension(session_store), &cookies).await;
    match response {
        (Codes::UNAUTHORIZED | Codes::NOTFOUND, Some(cookie), _) => {
            let clr_cookie = del_session_cookie(cookie);
            (cookies.remove(clr_cookie), code_response!(Codes::REDIRECT, "Invalid session")).into_response()
        },
        (Codes::FOUND, _, Some(user)) => {
            let pid = match cookies.get("projectId") {
                Some(c) => c.value(),
                None => return Redirect::to("/profile").into_response()
            };

            let res =
                sqlx::query_as::<_, Project>("SELECT * FROM Projects WHERE id = ?")
                    .bind(pid)
                    .fetch_optional(&*pool)
                    .await;

            let project: Project = match res {
                Ok(Some(p)) => p,
                Ok(None) => return code_response!(Codes::NOTFOUND, "Invalid project id"),
                Err(e) => { println!("1 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
            };

            let res =
                sqlx::query_as::<_, Int>(
                "SELECT permission_level AS value FROM Permissions
                 WHERE user_id = ? AND project_id = ?")
                    .bind(user.id).bind(project.id)
                    .fetch_optional(&*pool)
                    .await;

            let permission_level = match res {
                Ok(Some(r)) => r,
                Ok(None) => return code_response!(Codes::UNAUTHORIZED, "User not authorized on project"),
                Err(e) => { println!("2 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
            };

            let res =
                sqlx::query_as::<_, Profile>("
                SELECT u.id, u.username FROM Users AS u
                JOIN Permissions AS perm ON u.id = perm.user_id
                WHERE perm.project_id = ?")
                    .bind(project.id)
                    .fetch_all(&*pool)
                    .await;

            let users: Vec<Profile> = match res {
                Ok(usr) => usr,
                Err(e) => { println!("3 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
            };

            let res =
                sqlx::query_as::<_, TicketRaw>("
                SELECT t.id, t.name, t.status, t.category FROM Tickets AS t
                WHERE t.project_id = ?
                ")
                    .bind(project.id)
                    .fetch_all(&*pool)
                    .await;

            // assemble tickets
            let tickets_raw: Vec<TicketRaw> = match res {
                Ok(v) => v,
                Err(e) => { println!("4 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
            };

            let mut tickets: Vec<Ticket> = vec![];
            for ticket in tickets_raw {
                // fetch assigned users metadata
                let res =
                    sqlx::query_as::<_, Profile>("
                    SELECT tu.id, u.username FROM Users AS u
                    JOIN TicketUsers AS tu ON u.id = tu.user_id
                    WHERE tu.ticket_id = ?")
                        .bind(ticket.id)
                        .fetch_all(&*pool)
                        .await;

                let t_users: Vec<Profile> = match res {
                    Ok(v) => v,
                    Err(e) => { println!("5 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
                };

                // fetch ticket comments metadata
                let res =
                    sqlx::query_as::<_, Comment>("
                    SELECT u.username, c.content FROM Users AS u
                    JOIN Comments AS c ON u.id = c.user_id
                    WHERE c.ticket_id = ?")
                        .bind(ticket.id)
                        .fetch_all(&*pool)
                        .await;

                let comments: Vec<Comment> = match res {
                    Ok(v) => v,
                    Err(e) => { println!("6 {}", e); return code_response!(Codes::FAIL, "Internal error"); }
                };
                let t: Ticket = Ticket {
                    ticket_info: ticket,
                    users: t_users,
                    comments
                };
                tickets.push(t)
            }

            Json(json!(
            {
                "permission": permission_level,
                "project": project,
                "owner": user.username,
                "users": users,
                "tickets": tickets,
                "code": Codes::SUCCESS
            }
            )).into_response()
        },
        _ => Redirect::to("/login").into_response()
    }
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

