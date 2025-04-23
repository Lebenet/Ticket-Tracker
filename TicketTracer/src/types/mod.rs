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
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Project {
    pub id: i32,
    pub name: String,
    pub create_time: Option<NaiveDateTime>,
    pub owner_id: i32
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String
}

#[derive(Deserialize, Debug)]
pub struct PasswordRequest {
    pub old: String,
    pub new: String
}

impl PasswordRequest {
    pub fn is_valid(&self) -> bool {
        self.old != self.new && self.old != "" && self.new != ""
    }
}

// to send pretty ints with json
#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Int {
    pub value: i32
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Profile {
    pub id: i32,
    pub username: String
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct TicketRaw {
    pub id: i32,
    pub name: String,
    pub status: String,
    pub category: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ticket {
    pub ticket_info: TicketRaw,
    pub users: Vec<Profile>,
    pub comments: Vec<Comment>
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Comment {
    pub username: String,
    pub content: String
}

#[derive(Debug, Serialize_repr, Eq, PartialEq)]
#[repr(i32)]
pub enum Codes {
    SUCCESS = 1,
    FAIL = 2,
    UNAUTHORIZED = 3,
    NOTFOUND = 4,
    FOUND = 5,
    REDIRECT = 6
}

pub type SessionStore = Arc<Mutex<HashMap<String, i32>>>;
pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}