use crate::database::repositories::user_repo::UserRepositoryImpl;
use domain::modules::auth::UserRepository;
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, MockDatabase, Schema, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_find_by_email_found() {
    let user_id = Uuid::new_v4();
    let email = "test@example.com";

    // Construct row as BTreeMap, which implements IntoMockRow
    let mut row_map = BTreeMap::new();
    row_map.insert("id", Value::from(user_id));
    row_map.insert("email", Value::from(email));
    row_map.insert("password_hash", Value::from("hash"));
    row_map.insert("email_verified", Value::from(true));
    row_map.insert("verification_token", Value::String(None));
    row_map.insert(
        "verification_token_expires_at",
        Value::ChronoDateTimeWithTimeZone(None),
    );

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![vec![row_map]])
        .into_connection();

    let repo = UserRepositoryImpl::new(Arc::new(db));
    let result = repo.find_by_email(email).await.unwrap();

    assert!(result.is_some());
    let user = result.unwrap();
    assert_eq!(user.email, email);
    assert_eq!(user.id, user_id);
}

#[tokio::test]
async fn test_find_by_email_not_found() {
    let email = "nonexistent@example.com";

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![
            // Empty result set
            Vec::<BTreeMap<&str, Value>>::new(),
        ])
        .into_connection();

    let repo = UserRepositoryImpl::new(Arc::new(db));
    let result = repo.find_by_email(email).await.unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_sqlite_integration_save_and_find() {
    use sea_orm::sea_query::SqliteQueryBuilder;

    // 1. Connect to in-memory SQLite
    let db = Database::connect("sqlite::memory:").await.unwrap();

    // 2. Create schema from User entity
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    let stmt = schema.create_table_from_entity(crate::database::entities::users::Entity);

    let sql = stmt.to_string(SqliteQueryBuilder);
    db.execute_unprepared(&sql)
        .await
        .expect("Failed to create table");

    // 3. Test Repository
    let repo = UserRepositoryImpl::new(Arc::new(db));

    let user_id = Uuid::new_v4();
    let email = "sqlite@example.com".to_string();
    let user = domain::modules::auth::User {
        id: user_id,
        email: email.clone(),
        password_hash: "hashed".to_string(),
        email_verified: false,
        verification_token: None,
        verification_token_expires_at: None,
    };

    // Save
    let saved = repo.save(&user).await.expect("Failed to save user");
    assert_eq!(saved.id, user_id);

    // Find
    let found = repo
        .find_by_email(&email)
        .await
        .expect("Failed to find user");
    assert!(found.is_some());
    let found_user = found.unwrap();
    assert_eq!(found_user.email, email);
    assert_eq!(found_user.id, user_id);
}
