use crate::{
    auth_utils::get_user_id,
    error_codes::{ErrorCode, ErrorResponse},
    state::AppState,
    validation::ValidatedNoteInput,
};
use chrono::Utc;
use domain::modules::notes::{Note, NoteError};
use tauri::State;
use tracing::{error, info};
use uuid::Uuid;

/// Helper function to retrieve authentication token from secure storage
async fn get_required_token(state: &State<'_, AppState>, action: &str) -> Result<String, String> {
    let token_option = crate::commands::secure_storage::get_auth_token(state.clone())
        .await
        .map_err(|e| {
            error!(action = action, outcome = "failure", reason = "secure_storage_error", error = %e);
            String::from(ErrorResponse::new(ErrorCode::SecureStorageError, "Failed to retrieve authentication token"))
        })?;

    token_option.ok_or_else(|| String::from(ErrorResponse::from_code(ErrorCode::AuthRequired)))
}

/// Helper function to get user ID from authentication token
async fn get_user_id_from_token(state: &State<'_, AppState>, action: &str) -> Result<Uuid, String> {
    let token = get_required_token(state, action).await?;
    get_user_id(state, &token)
}

/// Helper function to map note errors to user-friendly messages with error codes
fn map_note_error(e: NoteError, uid: Uuid, note_id: Uuid, action: &str) -> String {
    match e {
        NoteError::NotFound | NoteError::Forbidden | NoteError::Unauthorized => {
            info!(
                user_id = %uid,
                note_id = %note_id,
                action = action,
                outcome = "failure",
                reason = "not_found_or_forbidden"
            );
            String::from(ErrorResponse::from_code(ErrorCode::NoteNotFound))
        }
        other => {
            error!(
                user_id = %uid,
                note_id = %note_id,
                action = action,
                outcome = "failure",
                error = %other,
                message = format!("Failed to {action} note in repository")
            );
            String::from(ErrorResponse::new(
                ErrorCode::InternalError,
                format!("Failed to {action}"),
            ))
        }
    }
}

/// Retrieves all notes for authenticated user
///
/// # Errors
///
/// This function will return an error if:
/// - No authentication token is found in secure storage
/// - The authentication token is invalid or expired
/// - Internal server errors occur while fetching notes
#[tauri::command]
pub async fn get_notes(state: State<'_, AppState>) -> Result<Vec<Note>, String> {
    let uid = get_user_id_from_token(&state, "get_notes").await?;
    let notes = state.note_repo.find_all_by_user(uid).await.map_err(|e| {
        error!(
            user_id = %uid,
            action = "fetch_notes",
            outcome = "failure",
            error = %e,
            message = "Failed to fetch notes from repository"
        );
        String::from(ErrorResponse::new(
            ErrorCode::InternalError,
            "Failed to fetch notes",
        ))
    })?;
    info!(user_id = %uid, action = "fetch_notes", outcome = "success");
    Ok(notes)
}

/// Creates a new note for authenticated user
///
/// # Errors
///
/// This function will return an error if:
/// - The authentication token is invalid or expired
/// - The note title or content is invalid
/// - Internal server errors occur while creating note
#[tauri::command]
pub async fn create_note(
    state: State<'_, AppState>,
    title: String,
    content: String,
) -> Result<Note, String> {
    let uid = get_user_id_from_token(&state, "create_note").await?;

    let validated_input = ValidatedNoteInput::new(title.as_str(), &content)?;

    let now = Utc::now();
    let note = Note {
        id: Uuid::new_v4(),
        user_id: uid,
        title: validated_input.title,
        content: validated_input.content,
        created_at: now,
        updated_at: now,
    };

    let saved_note = state.note_repo.create(&note).await.map_err(|e| {
        error!(
            user_id = %uid,
            note_id = %note.id,
            action = "create_note",
            outcome = "failure",
            error = %e,
            message = "Failed to create note in repository"
        );
        String::from(ErrorResponse::new(
            ErrorCode::InternalError,
            "Failed to create note",
        ))
    })?;
    info!(user_id = %uid, note_id = %saved_note.id, action = "create_note", outcome = "success");
    Ok(saved_note)
}

/// Deletes a note for authenticated user
///
/// # Errors
///
/// This function will return an error if:
/// - The authentication token is invalid or expired
/// - The note ID is invalid
/// - The note doesn't exist or doesn't belong to user
/// - Internal server errors occur while deleting note
#[tauri::command]
pub async fn delete_note(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let uid = get_user_id_from_token(&state, "delete_note").await?;
    let note_id = Uuid::parse_str(&id).map_err(|_| {
        error!(user_id = %uid, action = "delete_note", outcome = "failure", reason = "invalid_id_format");
        String::from(ErrorResponse::from_code(ErrorCode::InvalidNoteId))
    })?;

    state
        .note_repo
        .delete(note_id, uid)
        .await
        .map_err(|e| map_note_error(e, uid, note_id, "delete"))?;
    info!(user_id = %uid, note_id = %note_id, action = "delete_note", outcome = "success");
    Ok(())
}

/// Updates an existing note for authenticated user
///
/// # Errors
///
/// This function will return an error if:
/// - The authentication token is invalid or expired
/// - The note ID is invalid
/// - The note doesn't exist or doesn't belong to user
/// - The note title or content is invalid
/// - Internal server errors occur while updating note
#[tauri::command]
pub async fn update_note(
    state: State<'_, AppState>,
    id: String,
    title: String,
    content: String,
) -> Result<Note, String> {
    let uid = get_user_id_from_token(&state, "update_note").await?;
    let note_id = Uuid::parse_str(&id).map_err(|_| {
        error!(user_id = %uid, action = "update_note", outcome = "failure", reason = "invalid_id_format");
        String::from(ErrorResponse::from_code(ErrorCode::InvalidNoteId))
    })?;

    let validated_input = ValidatedNoteInput::new(title.as_str(), &content)?;

    // Fetch existing note to verify ownership and preserve created_at
    // Only fetch note if it belongs to authenticated user
    let existing_note = state
        .note_repo
        .find_by_id_and_user(note_id, uid)
        .await
        .map_err(|e| map_note_error(e, uid, note_id, "find"))?;

    let original_created_at = if let Some(note) = existing_note {
        note.created_at
    } else {
        info!(
            user_id = %uid,
            note_id = %note_id,
            action = "update_note",
            outcome = "failure",
            reason = "not_found"
        );
        return Err(String::from(ErrorResponse::from_code(
            ErrorCode::NoteNotFound,
        )));
    };

    // Create updated note object, preserving original created_at
    let now = Utc::now();
    let updated_note = Note {
        id: note_id,
        user_id: uid,
        title: validated_input.title,
        content: validated_input.content,
        created_at: original_created_at, // Preserve original creation time
        updated_at: now,
    };

    let saved_note = state
        .note_repo
        .update(&updated_note)
        .await
        .map_err(|e| map_note_error(e, uid, updated_note.id, "update"))?;
    info!(
        user_id = %uid,
        note_id = %saved_note.id,
        action = "update_note",
        outcome = "success"
    );
    Ok(saved_note)
}
