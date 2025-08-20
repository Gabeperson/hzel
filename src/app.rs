use axum::{
    debug_handler,
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
};
use fastcdc::v2020::{Chunk, FastCDC};
use futures_util::StreamExt;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool, query};
use std::path::Path;
use tap::TapFallible;
use tokio::{fs, io::AsyncWriteExt};
use tracing::{error, warn};
use typeshare::typeshare;
use uuid::Uuid;

use crate::{AppState, auth::Auth, database::NewVersion};

#[typeshare]
#[derive(Debug, FromRow, Serialize)]
pub struct User {
    pub name: String,
    pub password_hash: String,
    pub storage_limit_bytes: i64,
    pub created_at: i64,
}

#[typeshare]
#[derive(Debug, FromRow, Serialize)]
pub struct Item {
    pub id: String,
    pub owner_id: String,
    pub parent_id: Option<String>,
    pub path: String,
    pub storage_path: String,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub typ: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadMetadata {
    size: i64,
}

#[debug_handler]
pub async fn upload(
    State(state): State<AppState>,
    auth: Auth,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, StatusCode> {
    let user = auth.user.ok_or(StatusCode::UNAUTHORIZED)?;

    let AppState { db, files, .. } = state;

    let transaction_id = db.get_transaction_id(&user.username).await?;

    let mut completed_files = 0;

    let block = async {
        loop {
            let metadata = multipart
                .next_field()
                .await
                .tap_err(|e| warn!("Err reading multipart: {e}"))
                .map_err(|e| e.status())?;
            let Some(metadata) = metadata else {
                return Ok(());
            };
            let s = metadata.text().await.map_err(|e| e.status())?;
            let metadata: UploadMetadata =
                serde_json::from_str(&s).map_err(|_e| StatusCode::BAD_REQUEST)?;

            if metadata.size < 0 {
                return Err(StatusCode::BAD_REQUEST);
            }

            // TODO FIXME: quota + server side hashing impl
            // TODO FIXME: Add symlink-esque versions
            // TODO FIXME: test upload paths (duplicated)

            let file_data = multipart
                .next_field()
                .await
                .tap_err(|e| warn!("Error reading multipart: {e}"))
                .map_err(|e| e.status())?;

            let Some(mut field) = file_data else {
                return Err(StatusCode::BAD_REQUEST);
            };

            let path = field.file_name().ok_or(StatusCode::BAD_REQUEST)?.to_owned();

            let id = db
                .get_item_or_create(&user.username, transaction_id, &path)
                .await?;

            let new_version = NewVersion {
                item_id: id,
                size: metadata.size,
                transaction_id,
            };
            let new_ver_id = db.insert_new_version(new_version).await?;

            let mut curr_size = 0;

            // 1mb buffer
            let mut buf = Vec::<u8>::with_capacity(1024 * 1024);

            const MIN_CHUNK_SIZE: u32 = 64 * 1024;
            const AVG_CHUNK_SIZE: u32 = 128 * 1024;
            const MAX_CHUNK_SIZE: u32 = 256 * 1024;
            let mut chunks = Vec::new();
            let mut index = 0;
            loop {
                match field.chunk().await.map_err(|e| e.status())? {
                    Some(data) => {
                        buf.extend_from_slice(&data);
                        let cdc =
                            FastCDC::new(&buf, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE);
                        chunks.extend(cdc.into_iter());
                        chunks.pop();
                        if chunks.len() == 0 {
                            continue;
                        }

                        for chunk in chunks.iter() {
                            let hash = db
                                .create_chunk(&buf[chunk.offset..chunk.offset + chunk.length])
                                .await?;
                            // Insert version_chunks connection
                            todo!()
                        }
                    }
                    None => {
                        let cdc =
                            FastCDC::new(&buf, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE);
                        chunks.extend(cdc.into_iter());
                        if chunks.len() == 0 {
                            // TODO: verify this is right
                            break;
                        }

                        for chunk in chunks.iter() {
                            let hash = db
                                .create_chunk(&buf[chunk.offset..chunk.offset + chunk.length])
                                .await?;
                            // Insert version_chunks connection
                            todo!()
                        }
                    }
                }

                chunks.clear();
            }

            // There's no way someone's uploading more than 9 exabytes...

            completed_files += 1;
        }
    };

    let result = block.await;

    if let Err(e) = result {
        warn!(
            "Rolling back {completed_files} files for user {}",
            user.username
        );
        db.rollback_transaction(transaction_id).await?;
        return Err(e);
    }

    Ok(StatusCode::OK)
}
