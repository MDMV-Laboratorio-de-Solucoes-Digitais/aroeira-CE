use sea_orm::DbErr;

// PostgreSQL error code for unique_violation.
pub const POSTGRES_ERROR_UNIQUE_VIOLATION: &str = "23505";
// SQLite extended code: 2067 (SQLITE_CONSTRAINT_UNIQUE)
pub const SQLITE_ERROR_UNIQUE_CONSTRAINT: &str = "2067";
// SQLite extended code: 1555 (SQLITE_CONSTRAINT_PRIMARYKEY)
pub const SQLITE_ERROR_PRIMARYKEY_CONSTRAINT: &str = "1555";
// MySQL error code: 1062 (ER_DUP_ENTRY)
pub const MYSQL_ERROR_UNIQUE_VIOLATION: &str = "1062";

/// Helper function to determine if the error is a unique constraint violation.
///
/// This function handles different database backends and their specific error formats.
/// Avoid tight coupling to a specific `sqlx` version/DatabaseError trait object.
#[must_use]
pub fn is_unique_constraint_violation(error: &DbErr) -> bool {
    // Try to extract database-specific error codes first for more reliable detection
    let sqlx_err_opt = match error {
        DbErr::Query(sea_orm::RuntimeErr::SqlxError(e))
        | DbErr::Exec(sea_orm::RuntimeErr::SqlxError(e)) => Some(e),
        _ => None,
    };

    if let Some(sqlx_err) = sqlx_err_opt
        && let Some(db_err) = sqlx_err.as_database_error()
        && let Some(code) = db_err.code()
    {
        match code.as_ref() {
            POSTGRES_ERROR_UNIQUE_VIOLATION
            | MYSQL_ERROR_UNIQUE_VIOLATION
            | SQLITE_ERROR_UNIQUE_CONSTRAINT
            | SQLITE_ERROR_PRIMARYKEY_CONSTRAINT => return true, // PostgreSQL, MySQL, SQLite
            _ => {}
        }
    }

    // Fallback to string matching for other cases or older versions
    let msg = error.to_string().to_lowercase();
    msg.contains("unique constraint")
        || msg.contains("duplicate key")
        || msg.contains("duplicate entry")
}
