use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

pub const DB_PATH: &str = "./gemini_tokens.db";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub user_email: String,
    pub static_token: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub project_id: Option<String>,
}

/// 初始化数据库，如果表不存在则创建它。
pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tokens (
            user_email TEXT PRIMARY KEY,
            static_token TEXT NOT NULL UNIQUE,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            project_id TEXT
        )",
        [],
    )?;
    Ok(())
}

/// 保存或更新一个 token 记录。
pub fn save_token(conn: &Connection, record: &TokenRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO tokens (user_email, static_token, access_token, refresh_token, expires_at, project_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.user_email,
            record.static_token,
            record.access_token,
            record.refresh_token,
            record.expires_at,
            record.project_id,
        ],
    )?;
    Ok(())
}

/// 根据静态 token 查找一个 token 记录。
pub fn get_token(conn: &Connection, static_token: &str) -> Result<Option<TokenRecord>> {
    let mut stmt = conn.prepare(
        "SELECT user_email, static_token, access_token, refresh_token, expires_at, project_id FROM tokens WHERE static_token = ?1",
    )?;
    let mut rows = stmt.query(params![static_token])?;

    if let Some(row) = rows.next()? {
        Ok(Some(TokenRecord {
            user_email: row.get(0)?,
            static_token: row.get(1)?,
            access_token: row.get(2)?,
            refresh_token: row.get(3)?,
            expires_at: row.get(4)?,
            project_id: row.get(5)?,
        }))
    } else {
        Ok(None)
    }
}

/// 根据静态 token 删除一个 token 记录。
pub fn delete_token(conn: &Connection, static_token: &str) -> Result<usize> {
    conn.execute("DELETE FROM tokens WHERE static_token = ?1", params![static_token])
}

/// 创建一个线程安全的数据库连接池（这里简化为单个 Mutex 保护的连接）。
pub fn create_db_pool() -> Arc<Mutex<Connection>> {
    let conn = Connection::open(DB_PATH).expect("Failed to open database");
    init_db(&conn).expect("Failed to initialize database");
    Arc::new(Mutex::new(conn))
}
