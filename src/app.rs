use axum::{
    debug_handler,
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
};
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

use crate::{AppState, auth::Auth};

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
    pub size: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadMetadata<'a> {
    hash: &'a str,
}

#[debug_handler]
pub async fn upload(
    State(state): State<AppState>,
    auth: Auth,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, StatusCode> {
    let user = auth.user.ok_or(StatusCode::UNAUTHORIZED)?;

    let AppState { db, files, .. } = state;

    let transaction_id = query("INSERT INTO transaction_ids (committed) VALUES (0)")
        .execute(&db)
        .await
        .tap_err(|e| warn!("Error getting transaction ID: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .last_insert_rowid();

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
            let name = metadata
                .file_name()
                .ok_or(StatusCode::BAD_REQUEST)?
                .to_owned();
            let s = metadata.text().await.map_err(|e| e.status())?;
            let metadata: UploadMetadata =
                serde_json::from_str(&s).map_err(|_e| StatusCode::BAD_REQUEST)?;

            let hash = query(
                r#"
                    SELECT niv.hash
                    FROM users u
                    JOIN items i ON i.owner_id = u.name
                    JOIN newest_item_versions niv ON niv.item_id = i.id
                    WHERE u.name = ?
                        AND i.path = ?
                        AND i.deleted = 0;
                "#,
            )
            .bind(&user.username)
            .bind(&name)
            .fetch_optional(&db)
            .await
            .tap_err(|e| warn!("Error fetching hash: {e}"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let hash: Option<String> = hash.map(|row| row.get("hash"));

            if let Some(hash) = hash
                && hash == metadata.hash
            {
                // If the hash is the same, it means the file is the same
                // so we don't actually need to handle this file (because the delta is nothing)
                // so we just skip the data field and go on to the next file
                let _field = multipart
                    .next_field()
                    .await
                    .tap_err(|e| warn!("Err reading multipart: {e}"))
                    .map_err(|e| e.status())?;
                continue;
            }

            // Hash is different, so we need to make a new file version and write file to disk
            let file_data = multipart
                .next_field()
                .await
                .tap_err(|e| warn!("Error reading multipart: {e}"))
                .map_err(|e| e.status())?;

            let Some(mut field) = file_data else {
                return Err(StatusCode::BAD_REQUEST);
            };

            let item_id = get_item_or_create(&db, &user.username, transaction_id, &name).await?;

            let new_version =
                query("SELECT version_number FROM newest_item_versions WHERE item_id = ?")
                    .bind(&item_id)
                    .fetch_optional(&db)
                    .await
                    .tap_err(|e| warn!("Error selecting newest version number: {e}"))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let new_version = new_version.map(|r| r.get("version_number")).unwrap_or(0) + 1;

            let version_id = Uuid::new_v4();
            let id_string = version_id.to_string();

            let folder1 = &id_string[..2];
            let folder2 = &id_string[2..4];

            let storage_path = format!("{folder1}/{folder2}/{id_string}");

            let files = format!("{files}/{storage_path}");

            let path = Path::new(&files);
            let parent = path.parent().expect("We just formatted it");

            _ = fs::create_dir_all(parent).await;
            let mut file = fs::File::create_new(files)
                .await
                .tap_err(|e| warn!("Failed to create NEW file, UUID collision...?: {e}"))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let now = Timestamp::now().as_second();

            let mut size = 0;

            while let Some(bytes) = field.chunk().await.map_err(|e| e.status())? {
                size += bytes.len();
                file.write_all(&bytes)
                    .await
                    .tap_err(|e| warn!("Failed to write bytes to file: {e}"))
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }

            // There's no way someone's uploading more than 9 exabytes...
            let size = size as i64;

            let _res = query(
                "INSERT INTO item_versions
                (version_id, item_id, version_number, storage_path,
                created_at, size, hash, transaction_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id_string)
            .bind(item_id)
            .bind(new_version)
            .bind(storage_path)
            .bind(now)
            .bind(size)
            .bind(metadata.hash)
            .bind(transaction_id)
            .execute(&db)
            .await
            .tap_err(|e| warn!("Failed to insert new item version into DB: {e}"))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    };

    let result = block.await;

    if let Err(e) = result {
        let mut q = query("SELECT storage_path FROM item_versions WHERE transaction_id = $1")
            .bind(transaction_id)
            .fetch(&db);

        while let Some(res) = q.next().await {
            let Ok(res) = res else {
                error!("Couldn't delete record path after upload failure!");
                continue;
            };
            // Since we use create_new in the creation of the file, we know that
            // this can only refer to the failed transaction file, and not a live file.
            _ = fs::remove_file(res.get::<String, _>("storage_path")).await;
        }
        if query("DELETE FROM transaction_ids WHERE transaction_id = $1")
            .bind(transaction_id)
            .execute(&db)
            .await
            .is_err()
        {
            error!("Failed to delete transaction_id {transaction_id}!!");
        };
        return Err(e);
    }

    query("UPDATE transaction_ids SET committed = 1 WHERE transaction_id = $1")
        .bind(transaction_id)
        .execute(&db)
        .await
        .tap_err(|e| error!("Error committing transaction: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

async fn get_item_or_create(
    db: &SqlitePool,
    user: &str,
    transaction_id: i64,
    path: &str,
) -> Result<String, StatusCode> {
    let p = Path::new(path);
    let id = Uuid::new_v4().to_string();
    let parent = get_parent_id_or_create(db, user, transaction_id, p).await?;
    let now = Timestamp::now().as_second();
    let id = query(
        "INSERT INTO items (id, owner_id, parent_id, path, type, created_at, transaction_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(owner_id, path) DO UPDATE SET id = items.id RETURNING id",
    )
    .bind(id)
    .bind(user)
    .bind(parent)
    .bind(path)
    .bind("file")
    .bind(now)
    .bind(transaction_id)
    .fetch_one(db)
    .await
    .tap_err(|e| warn!("Error when getting/setting item: {e}"))
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id = id.get("id");
    Ok(id)
}

async fn get_parent_id_or_create(
    db: &SqlitePool,
    user: &str,
    transaction_id: i64,
    path: &Path,
) -> Result<Option<String>, StatusCode> {
    let Some(path) = path.parent() else {
        return Ok(None);
    };
    let path_str = path.to_str().unwrap();

    let res = query("SELECT id, type FROM items WHERE owner_id = $1 AND path = $2")
        .bind(user)
        .bind(path_str)
        .fetch_optional(db)
        .await
        .tap_err(|e| warn!("Err when checking parent status: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(r) = res {
        if r.get::<String, _>("type") == "file" {
            warn!("Tried to upload to file");
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(Some(r.get("id")));
    }

    let parent_id = Box::pin(get_parent_id_or_create(db, user, transaction_id, path)).await?;

    let now = Timestamp::now().as_second();

    let uuid = Uuid::new_v4().to_string();
    let _res = query(
        "INSERT INTO items (id, owner_id, parent_id, path, type, created_at, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&uuid)
    .bind(user)
    .bind(parent_id)
    .bind(path_str)
    .bind("folder")
    .bind(now)
    .bind(transaction_id)
    .execute(db)
    .await
    .tap_err(|e| warn!("Error inserting parent folder: {e}"))
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Some(uuid))
}
