// Xenon — instance administration.
//
// The first account to register is the admin. These routes are how that person
// looks after the instance: every account, every project, every resource,
// the unused invites.
// Session only — a leaked integration token must not become a roster of users.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, patch};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{self, Actor};
use crate::error::{AppError, AppResult};
use crate::event;
use crate::state::AppState;
use crate::util::now;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/admin/users", get(list_users))
        .route("/v1/admin/users/{id}", patch(update_user))
        .route("/v1/admin/projects", get(list_projects))
        .route("/v1/admin/projects/{project}", patch(update_project))
        .route("/v1/admin/resources", get(list_resources))
        .route("/v1/admin/resources/{id}", delete(delete_resource))
        .route("/v1/admin/invites", get(list_invites))
}

#[derive(Serialize)]
struct UserRef {
    id: String,
    email: String,
    display_name: String,
}

#[derive(Serialize)]
struct AdminUserView {
    id: String,
    email: String,
    display_name: String,
    is_admin: bool,
    created_at: i64,
    disabled_at: Option<i64>,
    project_count: i64,
}

#[derive(Serialize)]
struct AdminProjectView {
    id: String,
    slug: String,
    is_public: bool,
    github_repo: Option<String>,
    created_at: i64,
    resource_count: i64,
    owner: UserRef,
}

#[derive(Serialize)]
struct AdminInviteView {
    created_at: i64,
    expires_at: i64,
    used_at: Option<i64>,
    created_by: UserRef,
    used_by: Option<UserRef>,
}

#[derive(Serialize)]
struct ProjectRef {
    id: String,
    slug: String,
}

#[derive(Serialize)]
struct AdminResourceView {
    id: String,
    kind: String,
    slug: String,
    title: String,
    created_at: i64,
    updated_at: i64,
    revisions: i64,
    project: ProjectRef,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    disabled: bool,
}

#[derive(Deserialize)]
struct UpdateAdminProjectRequest {
    #[serde(default)]
    is_public: Option<bool>,
}

fn require_admin_session(conn: &Connection, headers: &HeaderMap) -> AppResult<Actor> {
    let actor = auth::require_actor(conn, headers)?;
    actor.require_session()?;
    actor.require_admin()?;
    Ok(actor)
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminUserView>>> {
    let conn = state.db();
    require_admin_session(&conn, &headers)?;
    Ok(Json(load_users(&conn)?))
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Json<AdminUserView>> {
    let conn = state.db();
    let actor = require_admin_session(&conn, &headers)?;

    let target = load_user(&conn, &id)?.ok_or_else(|| AppError::not_found("no such user"))?;
    if req.disabled && target.id == actor.user_id {
        return Err(AppError::forbidden(
            "cannot_disable_self",
            "you cannot disable your own account",
        ));
    }

    let already = target.disabled_at.is_some();
    if req.disabled != already {
        if req.disabled {
            conn.execute(
                "UPDATE user SET disabled_at = ?1 WHERE id = ?2",
                params![now(), id],
            )?;
            // The row going is what signs them out everywhere. Leaving the
            // sessions would still fail the next request (disabled_at is
            // checked), but a copied cookie would then say "disabled" instead
            // of "this session is gone", which is more than they need to hear.
            conn.execute("DELETE FROM session WHERE user_id = ?1", [&id])?;
        } else {
            conn.execute("UPDATE user SET disabled_at = NULL WHERE id = ?1", [&id])?;
        }
        let kind = if req.disabled {
            event::ACCOUNT_DISABLE
        } else {
            event::ACCOUNT_ENABLE
        };
        event::record(
            &conn,
            event::New::account(
                kind,
                &event::actor_name(&conn, &actor.user_id),
                &target.email,
            )
            .by(&actor)
            .detail(serde_json::json!({ "user_id": id })),
        )?;
    }

    load_user(&conn, &id)?
        .map(Json)
        .ok_or_else(|| AppError::not_found("no such user"))
}

async fn list_projects(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminProjectView>>> {
    let conn = state.db();
    require_admin_session(&conn, &headers)?;
    Ok(Json(load_projects(&conn)?))
}

async fn update_project(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(project): Path<String>,
    Json(req): Json<UpdateAdminProjectRequest>,
) -> AppResult<Json<AdminProjectView>> {
    let conn = state.db();
    let actor = require_admin_session(&conn, &headers)?;

    let current = load_project(&conn, &project)?
        .ok_or_else(|| AppError::not_found(format!("no project {project}")))?;

    if let Some(is_public) = req.is_public {
        if is_public != current.is_public {
            conn.execute(
                "UPDATE project SET is_public = ?1 WHERE id = ?2",
                params![i64::from(is_public), current.id],
            )?;
            event::record(
                &conn,
                event::New::project_scoped(
                    event::PROJECT_VISIBILITY,
                    &event::actor_name(&conn, &actor.user_id),
                    &project,
                )
                .by(&actor)
                .in_project(&current.id, &project)
                .detail(serde_json::json!({ "is_public": is_public })),
            )?;
        }
    }

    load_project(&conn, &project)?
        .map(Json)
        .ok_or_else(|| AppError::not_found(format!("no project {project}")))
}

async fn list_resources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminResourceView>>> {
    let conn = state.db();
    require_admin_session(&conn, &headers)?;
    Ok(Json(load_resources(&conn)?))
}

/// Take a resource off the instance. Revisions and file rows go with it;
/// activity stays (its `resource_id` becomes NULL) and blobs stay until GC.
/// Session-only, same as every other admin write: a leaked token must not
/// become a delete button.
async fn delete_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    state.tx(|tx| {
        let actor = require_admin_session(tx, &headers)?;
        let current =
            load_resource(tx, &id)?.ok_or_else(|| AppError::not_found("no such resource"))?;
        event::record(
            tx,
            event::New::project_scoped(
                event::RESOURCE_REMOVE,
                &event::actor_name(tx, &actor.user_id),
                &current.title,
            )
            .by(&actor)
            .in_project(&current.project.id, &current.project.slug)
            .about_resource(&current.id)
            .detail(serde_json::json!({
                "kind": current.kind,
                "slug": current.slug,
            })),
        )?;
        tx.execute("DELETE FROM resource WHERE id = ?1", [&current.id])?;
        Ok(StatusCode::NO_CONTENT)
    })
}

async fn list_invites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminInviteView>>> {
    let conn = state.db();
    require_admin_session(&conn, &headers)?;
    Ok(Json(load_invites(&conn)?))
}

fn load_users(conn: &Connection) -> AppResult<Vec<AdminUserView>> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.email, u.display_name, u.is_admin, u.created_at, u.disabled_at,
                (SELECT count(*) FROM project p WHERE p.owner_id = u.id)
         FROM user u
         ORDER BY u.created_at, u.email",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(AdminUserView {
                id: r.get(0)?,
                email: r.get(1)?,
                display_name: r.get(2)?,
                is_admin: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
                disabled_at: r.get(5)?,
                project_count: r.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_user(conn: &Connection, id: &str) -> AppResult<Option<AdminUserView>> {
    conn.query_row(
        "SELECT u.id, u.email, u.display_name, u.is_admin, u.created_at, u.disabled_at,
                (SELECT count(*) FROM project p WHERE p.owner_id = u.id)
         FROM user u WHERE u.id = ?1",
        [id],
        |r| {
            Ok(AdminUserView {
                id: r.get(0)?,
                email: r.get(1)?,
                display_name: r.get(2)?,
                is_admin: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
                disabled_at: r.get(5)?,
                project_count: r.get(6)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_projects(conn: &Connection) -> AppResult<Vec<AdminProjectView>> {
    let mut stmt = conn.prepare(
        "SELECT p.id, p.slug, p.is_public, p.github_repo, p.created_at,
                (SELECT count(*) FROM resource r WHERE r.project_id = p.id),
                u.id, u.email, u.display_name
         FROM project p
         JOIN user u ON u.id = p.owner_id
         ORDER BY p.created_at DESC, p.slug",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(AdminProjectView {
                id: r.get(0)?,
                slug: r.get(1)?,
                is_public: r.get::<_, i64>(2)? != 0,
                github_repo: r.get(3)?,
                created_at: r.get(4)?,
                resource_count: r.get(5)?,
                owner: UserRef {
                    id: r.get(6)?,
                    email: r.get(7)?,
                    display_name: r.get(8)?,
                },
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_project(conn: &Connection, slug: &str) -> AppResult<Option<AdminProjectView>> {
    conn.query_row(
        "SELECT p.id, p.slug, p.is_public, p.github_repo, p.created_at,
                (SELECT count(*) FROM resource r WHERE r.project_id = p.id),
                u.id, u.email, u.display_name
         FROM project p
         JOIN user u ON u.id = p.owner_id
         WHERE p.slug = ?1",
        [slug],
        |r| {
            Ok(AdminProjectView {
                id: r.get(0)?,
                slug: r.get(1)?,
                is_public: r.get::<_, i64>(2)? != 0,
                github_repo: r.get(3)?,
                created_at: r.get(4)?,
                resource_count: r.get(5)?,
                owner: UserRef {
                    id: r.get(6)?,
                    email: r.get(7)?,
                    display_name: r.get(8)?,
                },
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_resources(conn: &Connection) -> AppResult<Vec<AdminResourceView>> {
    let mut stmt = conn.prepare(
        "SELECT r.id, r.kind, r.slug, r.title, r.created_at, r.updated_at,
                (SELECT count(*) FROM revision v
                 WHERE v.resource_id = r.id AND v.sealed_at IS NOT NULL),
                p.id, p.slug
         FROM resource r
         JOIN project p ON p.id = r.project_id
         ORDER BY r.updated_at DESC, r.slug",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(AdminResourceView {
                id: r.get(0)?,
                kind: r.get(1)?,
                slug: r.get(2)?,
                title: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                revisions: r.get(6)?,
                project: ProjectRef {
                    id: r.get(7)?,
                    slug: r.get(8)?,
                },
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_resource(conn: &Connection, id: &str) -> AppResult<Option<AdminResourceView>> {
    conn.query_row(
        "SELECT r.id, r.kind, r.slug, r.title, r.created_at, r.updated_at,
                (SELECT count(*) FROM revision v
                 WHERE v.resource_id = r.id AND v.sealed_at IS NOT NULL),
                p.id, p.slug
         FROM resource r
         JOIN project p ON p.id = r.project_id
         WHERE r.id = ?1",
        [id],
        |r| {
            Ok(AdminResourceView {
                id: r.get(0)?,
                kind: r.get(1)?,
                slug: r.get(2)?,
                title: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                revisions: r.get(6)?,
                project: ProjectRef {
                    id: r.get(7)?,
                    slug: r.get(8)?,
                },
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_invites(conn: &Connection) -> AppResult<Vec<AdminInviteView>> {
    let mut stmt = conn.prepare(
        "SELECT i.created_at, i.expires_at, i.used_at,
                c.id, c.email, c.display_name,
                u.id, u.email, u.display_name
         FROM invite i
         JOIN user c ON c.id = i.created_by
         LEFT JOIN user u ON u.id = i.used_by
         ORDER BY i.created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let used_id: Option<String> = r.get(6)?;
            let used_email: Option<String> = r.get(7)?;
            let used_name: Option<String> = r.get(8)?;
            Ok(AdminInviteView {
                created_at: r.get(0)?,
                expires_at: r.get(1)?,
                used_at: r.get(2)?,
                created_by: UserRef {
                    id: r.get(3)?,
                    email: r.get(4)?,
                    display_name: r.get(5)?,
                },
                used_by: match (used_id, used_email, used_name) {
                    (Some(id), Some(email), Some(display_name)) => Some(UserRef {
                        id,
                        email,
                        display_name,
                    }),
                    _ => None,
                },
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
