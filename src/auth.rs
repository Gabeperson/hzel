use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{
    SignedCookieJar,
    cookie::{Cookie, Expiration},
};
use jiff::Timestamp;
use serde::Deserialize;
use session::{SessionManager, SessionStore};
use sqlx::{SqlitePool, error::ErrorKind, prelude::FromRow, query, query_as};
use tap::TapFallible as _;
use time::{Duration, OffsetDateTime};
use tracing::{error, warn};

use crate::AppState;

#[derive(Clone, FromRow, Debug)]
pub struct User {
    pub username: String,
    password_hash: String,
}

#[derive(Clone, Debug)]
pub struct Auth {
    pub user: Option<User>,
    session_token: Option<String>,
    pub db: SqlitePool,
    session_manager: SessionManager,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub enum AuthenticationError {
    Sqlx(sqlx::Error),
    TokioJoin(tokio::task::JoinError),
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationError::Sqlx(error) => {
                f.debug_tuple("AuthenicationError").field(error).finish()
            }
            AuthenticationError::TokioJoin(error) => {
                f.debug_tuple("AuthenticationError").field(error).finish()
            }
        }
    }
}

impl std::error::Error for AuthenticationError {}
impl From<sqlx::Error> for AuthenticationError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

impl From<tokio::task::JoinError> for AuthenticationError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::TokioJoin(value)
    }
}

impl Auth {
    async fn authenticate(&self, creds: Credentials) -> Result<Option<User>, AuthenticationError> {
        let user: Option<User> =
            query_as("SELECT name as username, password_hash FROM users WHERE name = $1")
                .bind(creds.username)
                .fetch_optional(&self.db)
                .await?;

        tokio::task::spawn_blocking(move || {
            Ok(user.filter(|user| {
                password_auth::verify_password(creds.password, &user.password_hash).is_ok()
            }))
        })
        .await?
    }

    async fn login(&self, user: User) -> String {
        self.session_manager.store.insert(user).await
    }

    async fn logout(&self) {
        if let Some(ref session) = self.session_token {
            self.session_manager.store.remove(session).await;
        }
    }

    async fn get_user(db: &SqlitePool, user_id: &str) -> Result<Option<User>, AuthenticationError> {
        let user = query_as("SELECT name as username, password_hash from users WHERE name = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
        Ok(user)
    }

    async fn register(&self, creds: Credentials) -> Result<(), sqlx::Error> {
        let hash = password_auth::generate_hash(creds.password);
        let now = Timestamp::now().as_second();
        query("INSERT INTO users (name, password_hash, created_at) VALUES (?, ?, ?)")
            .bind(creds.username)
            .bind(hash)
            .bind(now)
            .execute(&self.db)
            .await?;
        Ok(())
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookiejar = SignedCookieJar::from_headers(
            &parts.headers,
            state.session_manager.session_key.clone(),
        );
        let cookie = cookiejar.get(&state.session_manager.id);
        let mut session = None;
        let user = 'blck: {
            let Some(cookie) = cookie else {
                break 'blck None;
            };
            let creds = state.session_manager.store.get(cookie.value()).await;
            let Some(creds) = creds else { break 'blck None };
            let user = Auth::get_user(&state.db, &creds.username)
                .await
                .tap_err(|e| warn!("Error getting user from creds from db: {e}"))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(user) = user else { break 'blck None };
            session = Some(cookie.value().to_owned());
            Some(user)
        };

        Ok(Self {
            user,
            session_token: session,
            db: state.db.clone(),
            session_manager: state.session_manager.clone(),
        })
    }
}

pub async fn register(auth: Auth, Json(creds): Json<Credentials>) -> StatusCode {
    if let Err(e) = auth.register(creds).await {
        warn!("Error registering user: {e}");
        if let sqlx::Error::Database(d) = e
            && d.kind() == sqlx::error::ErrorKind::UniqueViolation
        {
            return StatusCode::CONFLICT;
        }
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

pub async fn login(
    cookie_jar: SignedCookieJar,
    auth_session: Auth,
    Json(creds): Json<Credentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            warn!("Login error: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let token = auth_session.login(user).await;
    let id: String = (*auth_session.session_manager.id).to_owned();
    let cookie = Cookie::build((id, token))
        .secure(auth_session.session_manager.secure)
        .http_only(true)
        .max_age(Duration::weeks(2));
    (StatusCode::OK, cookie_jar.add(cookie)).into_response()
}

pub async fn logout(auth_session: Auth) -> impl IntoResponse {
    auth_session.logout().await;
    StatusCode::OK
}

pub mod session {
    use std::{
        collections::{HashMap, hash_map::Entry},
        sync::Arc,
        time::Duration,
    };

    use axum_extra::extract::cookie::Key;
    use rand::Rng as _;
    use tokio::{
        sync::Mutex,
        time::{self, Instant},
    };

    use super::User;

    #[derive(Clone, Debug)]
    pub struct SessionManager {
        pub session_key: Key,
        pub id: Arc<str>,
        pub store: SessionStore,
        pub secure: bool,
    }

    impl SessionManager {
        pub async fn new(id: &str, ttl: Duration, secure: bool) -> Self {
            Self {
                session_key: Key::generate(),
                id: id.into(),
                store: SessionStore::new(ttl).await,
                secure,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SessionEntry {
        user: User,
        expires_at: Instant,
    }

    #[derive(Clone, Debug)]
    pub struct SessionStore {
        inner: Arc<Mutex<HashMap<String, SessionEntry>>>,
        ttl: Duration,
    }

    fn gen_256() -> String {
        let mut buf = [0u8; 32];
        rand::rng().fill(&mut buf);
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = String::with_capacity(64);
        for b in buf {
            s.push(HEX[b as usize >> 4] as char);
            s.push(HEX[b as usize & 0xF] as char);
        }
        s
    }

    impl SessionStore {
        pub async fn new(ttl: Duration) -> Self {
            let store = SessionStore {
                inner: Arc::new(Mutex::new(HashMap::new())),
                ttl,
            };
            store.spawn_cleanup_task().await;
            store
        }

        pub async fn insert(&self, user: User) -> String {
            let mut map = self.inner.lock().await;
            let mut entry = map.entry(gen_256());
            while let Entry::Occupied(_) = entry {
                entry = map.entry(gen_256());
            }
            let entry = entry.insert_entry(SessionEntry {
                user,
                expires_at: Instant::now() + self.ttl,
            });
            entry.key().clone()
        }

        pub async fn get(&self, key: &str) -> Option<User> {
            let mut map = self.inner.lock().await;
            if let Some(entry) = map.get_mut(key) {
                let now = Instant::now();
                if now < entry.expires_at {
                    // Refresh TTL on access
                    entry.expires_at = now + self.ttl;
                    return Some(entry.user.clone());
                } else {
                    map.remove(key);
                }
            }
            None
        }

        pub async fn remove(&self, key: &str) {
            let mut map = self.inner.lock().await;
            map.remove(key);
        }

        async fn spawn_cleanup_task(&self) {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let cleanup_interval = Duration::from_secs(60);
                let mut interval = time::interval(cleanup_interval);
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let mut map = inner.lock().await;
                    map.retain(|_, entry| entry.expires_at > now + Duration::from_secs(60));
                }
            });
        }
    }
}
