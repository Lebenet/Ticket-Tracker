macro_rules! code_response {
    ($code:expr) => {
        Json(json!({ "code": $code })).into_response()
    };
}

use std::{sync::Arc};
use axum::{Extension, Json, extract::State, response::{IntoResponse, Redirect, Response}};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde_json::json;
use rand::Rng;
use sqlx::{Error, MySqlPool};
use time::Duration;
use crate::types::*;

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
        let clr_cookie = del_session_cookie(cookie.clone());

        return (cookies.remove(clr_cookie), Redirect::to("/login")).into_response();
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

pub async fn profile(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    // check that session id is correct
    let result = check_session(State(pool.clone()), Extension(session_store), cookies.clone()).await;
    match result {
        (code @ (Codes::UNAUTHORIZED | Codes::NOTFOUND), cookie, _) => {
            let clr_cookie = del_session_cookie(cookie.unwrap().clone());
            (cookies.remove(clr_cookie), code_response!(code)).into_response()
        }
        (Codes::FOUND, _, user_opt) => {

            let user = user_opt.unwrap();

            // fetch projects where user's authorized (including his own)
            let projects: Vec<Project> = sqlx::query_as::<_, Project>(
                "SELECT * FROM Projects AS pr
          JOIN Permissions AS perm ON pr.id = perm.project_id
          WHERE perm.user_id = ?")
                .bind(user.id)
                .fetch_all(&*pool)
                .await
                .unwrap_or_else(|_| vec![]);

            // fetch other authorized users on each project, limit 5
            let mut users: Vec<Vec<Profile>> = vec![];
            let mut count: Vec<i32> = vec![];
            for p in &projects {
                // get list of 5 other members
                let p_users: Vec<Profile> =
                    sqlx::query_as::<_, Profile>(
                        "SELECT u.id, u.username FROM users AS u
            JOIN permissions AS perm ON u.id = perm.user_id
            WHERE perm.project_id = ?
            AND u.id != ?
            LIMIT 5")
                        .bind(p.id)
                        .bind(user.id)
                        .fetch_all(&*pool)
                        .await
                        .unwrap_or_else(|_| vec![]);

                //? Ugly, only temporary
                // get total count of those users
                let pm_c =
                    sqlx::query_as::<_, Int>("
            SELECT COUNT(*) AS value FROM
            (SELECT u.id, u.username FROM users AS u
            JOIN permissions AS perm ON u.id = perm.user_id
            WHERE perm.project_id = ?
            AND u.id != ?) as subquerry;")
                        .bind(p.id)
                        .bind(user.id)
                        .fetch_one(&*pool)
                        .await
                        .unwrap_or_else(|_| Int {value: 0});

                // add to the main lists
                users.push(p_users);
                count.push(pm_c.value);
            }

            // send response to client
            return Json(json!(
        {
            "user": user,
            "projects": projects,
            "users": users,
            "count": count,
            "code": Codes::SUCCESS
        }
    )).into_response();
        }
        _ => { // Redirect to /login if no valid session
            Redirect::to("/login").into_response()
        }
    }
}

pub async fn change_username(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    let response = check_session(State(pool.clone()), Extension(session_store), cookies.clone()).await;
    match response {
        _ => { code_response!(Codes::FAIL) } // Not Yet Implemented
    }
}

pub async fn reset_password(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    let response = check_session(State(pool.clone()), Extension(session_store), cookies.clone()).await;
    match response {
        _ => { code_response!(Codes::FAIL) } // Not Yet Implemented
    }
}

async fn check_session(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> (Codes, Option<Cookie<'static>>, Option<Profile>) {
    if let Some(cookie) = cookies.get("session_id") {
        // get session id from cookie jar
        let session_id: String = cookie.value().to_string();

        // fetch username from server sessions storage
        let username: String =
            session_store.lock().await
                .get(&session_id)
                .cloned()
                .unwrap_or_else(|| "".to_string());

        if username == "" {
            return (Codes::UNAUTHORIZED, Some(cookie.clone()), None);
        }

        // fetch user from database
        let user_opt: Option<Profile> =
            sqlx::query_as::<_, Profile>("SELECT id, username FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&*pool)
                .await
                .unwrap_or_else(|_| None);

        if user_opt.is_none() {
            return (Codes::NOTFOUND, Some(cookie.clone()), None);
        }
        (Codes::FOUND, None, user_opt)
    } else {
        (Codes::REDIRECT, None, None)
    }
}

fn generate_session_id() -> String {
    let mut rng = rand::rng();

    (0..32)  // Length of the session ID
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

async fn session_cookie(storage: SessionStore, username: String) -> Cookie<'static> {
    let session_id = generate_session_id();
    storage.lock().await.insert(session_id.clone(), username);

    let mut cookie = Cookie::new("session_id", session_id);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::hours(1));

    cookie.into_owned()
}

fn del_session_cookie(cookie: Cookie<'static>) -> Cookie<'static> {

    let mut cleared_cookie = Cookie::new(cookie.name(), "");
    cleared_cookie.set_path(cookie.path().unwrap_or_else(|| "/"));
    cleared_cookie.set_http_only(cookie.http_only().unwrap_or_else(|| false));
    cleared_cookie.set_max_age(Duration::seconds(0));

    cleared_cookie.into_owned()
}