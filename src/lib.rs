use std::{sync::Arc, time::Duration};

use anyhow::Error;
use app::upload;
use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRef},
    http::HeaderValue,
    response::Html,
    routing::{get, post},
};
use axum_extra::extract::cookie::Key;
use database::Database;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tower_http::cors::{AllowCredentials, AllowOrigin, CorsLayer};

mod app;
mod auth;
mod database;

use auth::{login, logout, register, session::SessionManager};

pub struct App {
    db: SqlitePool,
    files: String,
}

#[derive(Clone, Debug)]
pub struct AppState {
    db: Database,
    files: String,
    session_manager: SessionManager,
}

impl FromRef<AppState> for SqlitePool {
    fn from_ref(input: &AppState) -> Self {
        input.db.db.clone()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        input.session_manager.session_key.clone()
    }
}

impl App {
    pub async fn new(db_path: &str, files: String) -> Result<Self, Error> {
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .foreign_keys(true)
            .create_if_missing(true);
        let db = SqlitePool::connect_with(options).await?;
        sqlx::migrate!().run(&db).await?;
        Ok(App { db, files })
    }
    pub async fn serve(self) -> Result<(), Error> {
        //     // TODO FIXME make configurable

        let session_manager = SessionManager::new(
            "session_token",
            Duration::from_secs(7 * 24 * 60 * 60),
            false,
        )
        .await;

        let cors_layer = CorsLayer::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(AllowOrigin::exact(HeaderValue::from_static(
                "http://localhost:8080",
            )));

        let app = router(AppState {
            db: Database { db: self.db },
            files: self.files,
            session_manager,
        })
        .await
        // .layer(auth_layer)
        .layer(cors_layer);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown())
            .await?;

        Ok(())
    }
}

async fn shutdown() {
    tokio::signal::ctrl_c().await.unwrap()
}

async fn router(state: AppState) -> Router {
    Router::new()
        .route("/files", post(upload).layer(DefaultBodyLimit::disable()))
        // .route_layer(login_required!(Backend, login_url = "/login"))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/", get(async || Html(include_str!("../testpage.html"))))
        .with_state(state)
}
