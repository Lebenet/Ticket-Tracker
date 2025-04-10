use std::collections::HashMap;
use std::sync::Arc;
use serde_repr::Serialize_repr;
use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use chrono::NaiveDateTime;
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub create_time: Option<NaiveDateTime>, // Optional because it defaults to CURRENT_TIMESTAMP
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum Codes {
    SUCCESS = 1,
    FAIL = 2,
    UNAUTHORIZED = 3,
    NOTFOUND = 4,
    FOUND = 5
}

pub type SessionStore = Arc<Mutex<HashMap<String, String>>>;
pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}