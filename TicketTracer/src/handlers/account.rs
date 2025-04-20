macro_rules! code_response {
    ($code:expr, $message:expr) => {
        Json(json!({ "code": $code, "message": $message })).into_response()
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
        return code_response!(Codes::FAIL, "Invalid username or password");
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
                    session_store, row.id).await;

                let mut response = code_response!(Codes::SUCCESS, "");
                response.headers_mut().insert(
                    axum::http::header::SET_COOKIE,
                    cookie.to_string().parse().unwrap(),
                );

                response

            } else {
                code_response!(Codes::UNAUTHORIZED, "Wrong password")
            }
        }
        Err(Error::RowNotFound) => code_response!(Codes::NOTFOUND, "User not found"),
        Err(_) => code_response!(Codes::FAIL, "Internal error")
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
        return code_response!(Codes::FAIL, "Invalid username or password")
    }

    let check = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = ?"
    )
        .bind(&user.username)
        .fetch_optional(&*pool)
        .await
        .unwrap_or_else(|_| None);

    if check.is_some() {
        return code_response!(Codes::FOUND, "Username already in use");
    }

    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();

    let result = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?);",
        user.username,
        hashed_password
    )
        .execute(&*pool)
        .await;

    match result {
        Ok(r) => {
            let cookie = session_cookie(
                session_store, r.last_insert_id() as i32).await;

            let mut response = code_response!(Codes::SUCCESS, "");
            response.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                cookie.to_string().parse().unwrap(),
            );

            response
        },
        Err(_) => code_response!(Codes::FAIL, "Internal error")
    }

}

pub async fn profile(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar
) -> impl IntoResponse {
    // check that session id is correct
    let result = check_session(State(pool.clone()), Extension(session_store), &cookies).await;
    match result {
        (Codes::UNAUTHORIZED | Codes::NOTFOUND, Some(cookie), _) => {
            let clr_cookie = del_session_cookie(cookie);
            (cookies.remove(clr_cookie), code_response!(Codes::REDIRECT, "Invalid session")).into_response()
        }
        (Codes::FOUND, _, Some(user)) => {
            // fetch projects where user's authorized (including his own)
            let projects: Vec<Project> =
                sqlx::query_as::<_, Project>(
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
    cookies: CookieJar,
    Json(new_username): Json<LoginRequest>
) -> impl IntoResponse {
    let response = check_session(State(pool.clone()), Extension(session_store), &cookies).await;
    match response {
        (Codes::UNAUTHORIZED | Codes::NOTFOUND, Some(cookie), _) => {
            let clr_cookie = del_session_cookie(cookie);
            (cookies.remove(clr_cookie), code_response!(Codes::REDIRECT, "Invalid session")).into_response()
        }
        (Codes::FOUND, _, Some(user)) => {
            // check password
            if !verify(&new_username.password, &user.password_hash).unwrap_or(false) {
                // wrong password
                return code_response!(Codes::UNAUTHORIZED, "Wrong password");
            }

            let check: Result<Option<Profile>, Error> =
                sqlx::query_as::<_, Profile>("SELECT id, username FROM Users WHERE username = ?")
                    .bind(&new_username.username)
                    .fetch_optional(&*pool)
                    .await;

            match check {
                Ok(row) => {
                    // counter-intuitive, we actually want the row to not return anything
                    if row.is_none() {
                        // username not found, free to use
                        let result = sqlx::query!("UPDATE Users SET username = ? WHERE id = ?",
                    &new_username.username, user.id)
                            .execute(&*pool)
                            .await;

                        match result {
                            Ok(_) => { code_response!(Codes::SUCCESS, "") }
                            Err(_) => { code_response!(Codes::FAIL, "Internal error") }
                        }
                    } else {
                        // so if it returns, then username found and can't use it
                        code_response!(Codes::FOUND, "Username already in use") }
                    }

                Err(_) => { code_response!(Codes::FAIL, "Internal error") }
            }
        }
        _ => { Redirect::to("/login").into_response() }
    }
}

pub async fn reset_password(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: CookieJar,
    Json(p_request): Json<PasswordRequest>
) -> impl IntoResponse {
    let response = check_session(State(pool.clone()), Extension(session_store), &cookies).await;
    match response {
        (Codes::UNAUTHORIZED | Codes::NOTFOUND, Some(cookie), _) => {
            let clr_cookie = del_session_cookie(cookie);
            // sending "Codes::REDIRECT" back to the user to have an opportunity to tell the user
            // something is wrong with their session
            println!("invalid session");
            (cookies.remove(clr_cookie), code_response!(Codes::REDIRECT, "Invalid session")).into_response()
        }
        (Codes::FOUND, _, Some(user)) => {
            // Check that password request doesn't contain empty passwords
            if !p_request.is_valid() {
                println!("Invalid password request");
                return code_response!(Codes::UNAUTHORIZED, "Invalid password request")
            }

            // Check password
            if !verify(p_request.old, &user.password_hash).unwrap_or(false) {
                println!("Wrong password");
                return code_response!(Codes::UNAUTHORIZED, "Wrong password");
            }

            // Update password
            let password_hash = hash(p_request.new, DEFAULT_COST).unwrap();
            let result =
                sqlx::query!("UPDATE Users SET password_hash = ? WHERE id = ?",
                             password_hash, user.id)
                    .execute(&*pool)
                    .await;

            // Send response to client
            match result {
                Ok(_) => { println!("success"); code_response!(Codes::SUCCESS, "") }
                Err(_) => { println!("fail"); code_response!(Codes::FAIL, "Internal error") }
            }
        }
        // Here just a redirect because no session cookie was found
        _ => { println!("no session found"); Redirect::to("/login").into_response() }
    }
}

async fn check_session(
    State(pool): State<Arc<MySqlPool>>,
    Extension(session_store): Extension<SessionStore>,
    cookies: &CookieJar
) -> (Codes, Option<Cookie<'static>>, Option<User>) {
    let cookie: Cookie = match cookies.get("session_id") {
        Some(c) => c.to_owned(),
        None => return (Codes::REDIRECT, None, None)
    };

    // get session id from cookie jar
    let session_id: String = cookie.value().to_string();

    // fetch user id from server sessions storage
    let user_id: i32 =
        session_store.lock().await
            .get(&session_id)
            .cloned()
            .unwrap_or(0);
    if user_id == 0 {
        return (Codes::UNAUTHORIZED, Some(cookie), None);
    }

    // fetch user from database
    let user: Option<User> =
        sqlx::query_as::<_, User>("SELECT * FROM Users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&*pool)
            .await
            .unwrap_or(None);
    match user {
        None => (Codes::NOTFOUND, Some(cookie), None),
        _ => (Codes::FOUND, None, user)
    }
}

fn generate_session_id() -> String {
    let mut rng = rand::rng();

    (0..32)  // Length of the session ID
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

async fn session_cookie(storage: SessionStore, user_id: i32) -> Cookie<'static> {
    let session_id = generate_session_id();
    storage.lock().await.insert(session_id.clone(), user_id);

    new_cookie("session_id", &session_id, "/",
               true, Duration::hours(1))
}

fn del_session_cookie(cookie: Cookie<'static>) -> Cookie<'static> {
    // used to ensure same path and http_only
    new_cookie(cookie.name(), "", cookie.path().unwrap_or("/"),
               cookie.http_only().unwrap_or(false), Duration::seconds(0))
}

fn new_cookie(name: &str, value: &str, path: &str, http_only: bool, lifetime: Duration) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path(path);
    cookie.set_http_only(http_only);
    cookie.set_max_age(lifetime);

    cookie.into_owned()
}

/* DEBUG

use axum::{body::Body};
use http_body_util::BodyExt;
use bytes::Bytes;

pub async fn print_and_return_response(response: Response<Body>) -> Response<Body> {
    let (parts, body) = response.into_parts();

    // Buffer the full body
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();

            // Print the body as UTF-8 string if possible
            if let Ok(body_str) = std::str::from_utf8(&bytes) {
                println!("Response body: {}", body_str);
            } else {
                println!("Response body: <non-UTF8 data>");
            }

            // Rebuild response with original parts and cloned body
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(err) => {
            println!("Failed to read body: {}", err);
            Response::from_parts(parts, Body::from("Error reading body"))
        }
    }
}

use http::header::{HeaderMap, HeaderName};

pub async fn print_headers(response: Response) -> Response {
    // Get the headers from the response
    let headers: &HeaderMap = &response.headers();

    // Print each header's name and value
    for (key, value) in headers.iter() {
        println!("Header: {}: {:?}", key.as_str(), value);
    }

    // Return the response as is
    response
}

*/