use std::sync::Arc;
use axum::Extension;
use axum::extract::State;
use time::Duration;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use sqlx::MySqlPool;
use crate::types::{Codes, SessionStore, User};

pub fn del_session_cookie(cookie: Cookie<'static>) -> Cookie<'static> {
    // used to ensure same path and http_only
    new_cookie(cookie.name(), "", cookie.path().unwrap_or("/"),
               cookie.http_only().unwrap_or(false), Duration::seconds(0))
}

pub fn new_cookie(name: &str, value: &str, path: &str, http_only: bool, lifetime: Duration) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path(path);
    cookie.set_http_only(http_only);
    cookie.set_max_age(lifetime);

    cookie.into_owned()
}

pub async fn check_session(
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