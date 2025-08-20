use std::path::Path;

use axum::http::StatusCode;
use jiff::Timestamp;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tap::TapFallible as _;
use tracing::{error, warn};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Database {
    pub db: SqlitePool,
}

pub struct NewVersion {
    pub item_id: Uuid,
    pub size: i64,
    pub transaction_id: i64,
}

impl Database {
    pub async fn get_transaction_id(&self, user: &str) -> Result<i64, StatusCode> {
        let row = sqlx::query(
            "INSERT INTO transaction_ids (username, committed) VALUES (?, 0) RETURNING transaction_id",
        ).bind(user).fetch_one(&self.db).await.tap_err(|e| warn!("Error getting transaction id for user {user}: {e}")).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(row.get(0))
    }
    pub async fn create_chunk(&self, data: &[u8]) -> Result<[u8; 32], StatusCode> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash: [u8; 32] = hasher.finalize().into();
        let size = data.len();
        sqlx::query(
            "INSERT INTO chunks (hash, size, refcount, data) VALUES (?, ?, 1, ?)
            ON CONFLICT DO UPDATE SET refcount = refcount + 1",
        )
        .bind(&hash as &[u8])
        .bind(size as i64)
        .bind(data)
        .execute(&self.db)
        .await
        .tap_err(|e| warn!("Error inserting new chunk/incrementing refcount: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(hash)
    }
    pub async fn get_newest_version(&self, item_id: &[u8]) -> Result<Option<i64>, StatusCode> {
        let row = sqlx::query(
            "SELECT version_number FROM item_versions WHERE item_id = ? ORDER BY version_number DESC LIMIT 1"
        ).bind(item_id).fetch_optional(&self.db).await.tap_err(|e| warn!("Error getting latest version for item: {e}")).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(row.map(|r| r.get("version_number")))
    }
    pub async fn insert_new_version(&self, new_version: NewVersion) -> Result<Uuid, StatusCode> {
        let item_id = new_version.item_id.into_bytes();
        let version_id = Uuid::new_v4();
        let version_id_bytes = version_id.into_bytes();
        let version_number = self.get_newest_version(&item_id).await?.unwrap_or(0) + 1;
        let now = Timestamp::now().as_second();
        sqlx::query(
            "INSERT INTO item_versions
            (version_id, item_id, version_number, created_at, size, hash, transaction_id) VALUES
            (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&version_id_bytes as &[u8])
        .bind(&item_id as &[u8])
        .bind(version_number)
        .bind(now)
        .bind(new_version.size)
        .bind(&[] as &[u8])
        .bind(new_version.transaction_id)
        .execute(&self.db)
        .await
        .tap_err(|e| warn!("Error inserting new version: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(version_id)
    }
    pub async fn rollback_transaction(&self, transaction_id: i64) -> Result<(), StatusCode> {
        let fut = async {
            let mut tx = self.db.begin().await?;

            // Decr all refcounts
            sqlx::query(
                "UPDATE chunks SET refcount = refcount - 1
            WHERE hash IN (SELECT chunk_hash FROM version_chunks WHERE transaction_id = ?)",
            )
            .bind(transaction_id)
            .execute(&mut *tx)
            .await?;

            // Delete chunks connections
            sqlx::query("DELETE FROM version_chunks WHERE transaction_id = ?")
                .bind(transaction_id)
                .execute(&mut *tx)
                .await?;

            // Delete versions
            sqlx::query("DELETE FROM item_versions WHERE transaction_id = ?")
                .bind(transaction_id)
                .execute(&mut *tx)
                .await?;

            // Delete items created
            sqlx::query("DELETE FROM items WHERE transaction_id = ?")
                .bind(transaction_id)
                .execute(&mut *tx)
                .await?;

            // Delete unused chunks
            sqlx::query("DELETE FROM chunks WHERE refcount <= 0")
                .execute(&mut *tx)
                .await?;

            // TODO FIXME: See if cascade works
            // Remove the transaction row itself
            sqlx::query("DELETE FROM transaction_ids WHERE transaction_id = ?")
                .bind(transaction_id)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;
            Ok(())
        };
        let res: Result<(), sqlx::Error> = fut.await;
        match res {
            Ok(r) => Ok(r),
            Err(e) => {
                error!("Error resetting transaction: {e}");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
    pub async fn commit_transaction(&self, transaction_id: i64) -> Result<(), StatusCode> {
        if let Err(e) =
            sqlx::query("UPDATE transaction_ids SET committed = 1 WHERE transaction_id = ?")
                .bind(transaction_id)
                .execute(&self.db)
                .await
        {
            error!("Failed to set transaction committed: {e}");
            _ = self.rollback_transaction(transaction_id).await;
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        Ok(())
    }
    pub async fn get_item_or_create(
        &self,
        user: &str,
        transaction_id: i64,
        virt_file_path: &str,
    ) -> Result<Uuid, StatusCode> {
        let p = Path::new(virt_file_path);
        let id = Uuid::new_v4();
        let parent = self
            .get_parent_id_or_create(user, transaction_id, p)
            .await?;
        let now = jiff::Timestamp::now().as_second();

        let row = sqlx::query(
            "INSERT INTO items (id, owner_id, parent_id, path, type, created_at, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(owner_id, path) DO UPDATE SET id = items.id RETURNING id",
        )
        .bind(id.as_bytes().to_vec())
        .bind(user)
        .bind(parent.map(|p| p.as_bytes().to_vec()))
        .bind(virt_file_path)
        .bind("file")
        .bind(now)
        .bind(transaction_id)
        .fetch_one(&self.db)
        .await
        .tap_err(|e| warn!("Failed to create item: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let id_bytes: Vec<u8> = row.get("id");
        Uuid::from_slice(&id_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub async fn get_parent_id_or_create(
        &self,
        user: &str,
        transaction_id: i64,
        path: &Path,
    ) -> Result<Option<Uuid>, StatusCode> {
        let Some(parent_path) = path.parent() else {
            return Ok(None);
        };
        let parent_str = parent_path.to_str().ok_or(StatusCode::BAD_REQUEST)?;

        if let Some(row) = sqlx::query(
            "SELECT id, type FROM items WHERE owner_id = ? AND path = ? AND deleted = 0",
        )
        .bind(user)
        .bind(parent_str)
        .fetch_optional(&self.db)
        .await
        .tap_err(|e| warn!("Error when trying to fetch potential parent id: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            let ty: String = row.get("type");
            if ty == "file" {
                return Err(StatusCode::BAD_REQUEST);
            }
            let id_bytes: Vec<u8> = row.get("id");
            let uuid = Uuid::from_slice(&id_bytes)
                .tap_err(|e| warn!("Invalid UUID in database?: {e}"))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Ok(Some(uuid));
        }

        let parent_id =
            Box::pin(self.get_parent_id_or_create(user, transaction_id, parent_path)).await?;

        let uuid = Uuid::new_v4();
        let now = Timestamp::now().as_second();

        sqlx::query(
            "INSERT INTO items (id, owner_id, parent_id, path, type, created_at, transaction_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid.as_bytes().to_vec())
        .bind(user)
        .bind(parent_id.map(|p| p.as_bytes().to_vec()))
        .bind(parent_str)
        .bind("folder")
        .bind(now)
        .bind(transaction_id)
        .execute(&self.db)
        .await
        .tap_err(|e| warn!("Error inserting item parent: {e}"))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Some(uuid))
    }
}
