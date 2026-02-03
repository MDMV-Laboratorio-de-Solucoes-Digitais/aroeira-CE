<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { clearSessionId, logAuditEvent } from "$lib/audit";
  import { Button } from "$lib/components/ui/button";
  import * as Card from "$lib/components/ui/card";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import ResponsiveModal from "$lib/components/ui/responsive-modal/ResponsiveModal.svelte";
  import { Skeleton } from "$lib/components/ui/skeleton";
  import { getErrorMessage, isAuthRequired } from "$lib/error-handler";
  import { handleError, logError } from "$lib/logger";
  import { invoke } from "@tauri-apps/api/core";
  import {
    FileText,
    LogOut,
    Pencil,
    Plus,
    Search,
    Trash2,
  } from "lucide-svelte";
  import { onMount } from "svelte";

  interface Note {
    id: string;
    title: string;
    content: string;
    created_at: string;
    updated_at: string;
  }

  let notes = $state<Note[]>([]);
  let loading = $state(true);
  let error = $state("");
  let actionError = $state("");
  let searchQuery = $state("");

  let showModal = $state(false);
  import { Alert } from "$lib/components/ui/alert";
  import { CircleAlert } from "lucide-svelte";

  let editingNote = $state<Note | null>(null);
  let formTitle = $state("");
  let formContent = $state("");
  let formLoading = $state(false);
  let showDeleteDialog = $state(false);
  let noteToDelete = $state<string | null>(null);
  let showLogoutWarning = $state(false);
  let logoutErrorMessage = $state("");

  // Filtered notes
  let filteredNotes = $derived(
    notes.filter(
      (n) =>
        n.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.content.toLowerCase().includes(searchQuery.toLowerCase()),
    ),
  );

  onMount(async () => {
    await loadNotes();
  });

  async function loadNotes() {
    loading = true;
    error = "";
    try {
      notes = await invoke("get_notes");
      logAuditEvent("notes_load", true, { count: notes.length });
    } catch (err: unknown) {
      logAuditEvent("notes_load", false);

      // Check if error is authentication required
      if (isAuthRequired(err)) {
        await goto(resolve("/login"), { replaceState: true });
        return;
      }

      error = handleError(err, "load notes");
    } finally {
      loading = false;
    }
  }

  function openCreateModal() {
    editingNote = null;
    formTitle = "";
    formContent = "";
    actionError = "";
    showModal = true;
  }

  function openEditModal(note: Note) {
    editingNote = note;
    formTitle = note.title;
    formContent = note.content;
    actionError = "";
    showModal = true;
  }

  async function handleSave() {
    formLoading = true;
    actionError = "";
    try {
      if (editingNote) {
        await invoke("update_note", {
          id: editingNote.id,
          title: formTitle,
          content: formContent,
        });
        logAuditEvent("note_update", true, { id: editingNote.id });
      } else {
        await invoke("create_note", {
          title: formTitle,
          content: formContent,
        });
        logAuditEvent("note_create", true);
      }
      showModal = false;
      await loadNotes();
    } catch (err: unknown) {
      logAuditEvent(editingNote ? "note_update" : "note_create", false, {
        id: editingNote?.id,
      });
      actionError = handleError(err, "save note");
    } finally {
      formLoading = false;
    }
  }

  function openDeleteDialog(id: string) {
    noteToDelete = id;
    showDeleteDialog = true;
  }

  async function handleDelete() {
    if (!noteToDelete) return;
    actionError = "";
    try {
      await invoke("delete_note", { id: noteToDelete });
      logAuditEvent("note_delete", true, { id: noteToDelete });
      showDeleteDialog = false;
      noteToDelete = null;
      await loadNotes();
    } catch (err: unknown) {
      logAuditEvent("note_delete", false, { id: noteToDelete });
      actionError = handleError(err, "delete note");
    }
  }

  function cancelDelete() {
    showDeleteDialog = false;
    noteToDelete = null;
  }

  async function logout() {
    let backendLogoutFailed = false;
    try {
      await invoke("logout");
      logAuditEvent("logout", true);
    } catch (err) {
      backendLogoutFailed = true;
      logAuditEvent("logout", false);
      logError("logout", err);
      logoutErrorMessage = getErrorMessage(err);
    } finally {
      // Ensure session is cleared and user is redirected regardless of backend outcome.
      clearSessionId();

      if (backendLogoutFailed) {
        // Show warning dialog before redirecting
        showLogoutWarning = true;
      } else {
        // Successful logout, redirect immediately
        await goto(resolve("/login"), { replaceState: true });
      }
    }
  }

  function acknowledgeLogoutWarning() {
    showLogoutWarning = false;
    goto(resolve("/login"), { replaceState: true });
  }
</script>

<div
  class="flex h-full w-full flex-col overflow-hidden bg-background font-sans"
>
  <div class="flex flex-1 flex-col overflow-hidden p-4 md:p-8">
    <div class="mx-auto flex w-full max-w-5xl flex-1 flex-col space-y-8">
      <!-- Header -->
      <div
        class="flex flex-col justify-between gap-4 sm:flex-row sm:items-center"
      >
        <div class="space-y-1">
          <h1 class="text-3xl font-bold tracking-tight text-foreground">
            Dashboard
          </h1>
          <p class="text-muted-foreground">Manage your notes and ideas.</p>
        </div>
        <div class="flex gap-2">
          <Button
            class="gap-2 border border-border bg-card text-card-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            onclick={logout}
          >
            <LogOut size={16} /> Logout
          </Button>
          <Button onclick={openCreateModal} class="gap-2 shadow-sm">
            <Plus size={16} /> New Note
          </Button>
        </div>
      </div>

      <!-- Toolbar -->
      <div
        class="flex w-full max-w-md items-center space-x-2 rounded-lg border border-border bg-card p-2 shadow-sm sm:max-w-md"
      >
        <Search size={20} class="text-muted-foreground ml-2" />
        <input
          placeholder="Search notes..."
          bind:value={searchQuery}
          class="placeholder:text-muted-foreground h-9 flex-1 border-none bg-transparent text-sm text-foreground outline-none"
        />
      </div>

      {#if actionError && !showModal}
        <div
          class="text-destructive rounded-md border border-red-100 bg-red-50 p-3 text-sm"
        >
          {actionError}
        </div>
      {/if}

      <!-- Grid -->
      {#if loading}
        <div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {#each [1, 2, 3] as index (index)}
            <div class="space-y-3 rounded-lg border border-border bg-card p-4">
              <Skeleton class="h-6 w-3/4 rounded" />
              <Skeleton class="h-4 w-1/2 rounded" />
              <div class="space-y-2 pt-4">
                <Skeleton class="h-20 w-full rounded" />
              </div>
            </div>
          {/each}
        </div>
      {:else if error}
        <div
          class="text-destructive rounded-lg border border-red-100 bg-red-50 p-8 text-center"
        >
          <p>{error}</p>
        </div>
      {:else if filteredNotes.length === 0}
        <div
          class="rounded-lg border border-dashed border-border bg-card py-20 text-center"
        >
          <div class="mb-4 flex justify-center">
            <div class="rounded-full bg-muted p-3 text-muted-foreground">
              <FileText size={32} />
            </div>
          </div>
          <h3 class="text-lg font-medium text-foreground">No notes found</h3>
          <p class="text-muted-foreground mb-6">
            Get started by creating your first note.
          </p>
          <Button onclick={openCreateModal} class="gap-2">
            <Plus size={16} /> Create Note
          </Button>
        </div>
      {:else}
        <div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {#each filteredNotes as note (note.id)}
            <Card.Root
              class="flex h-full flex-col border-border bg-card text-card-foreground transition-shadow duration-200 hover:shadow-md"
            >
              <Card.Header>
                <Card.Title
                  class="line-clamp-1 text-lg font-semibold text-foreground"
                  >{note.title}</Card.Title
                >
                <Card.Description class="text-xs"
                  >{new Date(note.created_at).toLocaleDateString(undefined, {
                    dateStyle: "medium",
                  })}</Card.Description
                >
              </Card.Header>
              <Card.Content class="flex-1">
                <p
                  class="line-clamp-4 text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground"
                >
                  {note.content}
                </p>
              </Card.Content>
              <Card.Footer
                class="mt-auto flex justify-end gap-2 border-t border-border pt-4"
              >
                <Button
                  class="hover:text-primary h-8 w-8 border border-border bg-card p-0 text-muted-foreground hover:bg-accent"
                  onclick={() => openEditModal(note)}
                  title="Edit"
                  aria-label="Edit"
                  type="button"
                >
                  <Pencil size={14} />
                </Button>
                <Button
                  class="h-8 w-8 border border-border bg-card p-0 text-muted-foreground hover:border-destructive/50 hover:bg-destructive/10 hover:text-destructive"
                  onclick={() => openDeleteDialog(note.id)}
                  title="Delete"
                  aria-label="Delete"
                  type="button"
                >
                  <Trash2 size={14} />
                </Button>
              </Card.Footer>
            </Card.Root>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>

<ResponsiveModal
  bind:open={showModal}
  title={editingNote ? "Edit Note" : "Create Note"}
>
  {#snippet description()}
    {#if actionError}
      <Alert variant="destructive" class="mb-4">
        <CircleAlert class="size-4" />
        <div>{actionError}</div>
      </Alert>
    {/if}
  {/snippet}

  <div class="space-y-4">
    <div class="space-y-2">
      <Label class="text-foreground">Title</Label>
      <Input
        type="text"
        bind:value={formTitle}
        placeholder="Enter a descriptive title..."
        class="border-input bg-input/10 transition-colors focus:bg-background"
      />
    </div>
    <div class="space-y-2">
      <Label class="text-foreground">Content</Label>
      <textarea
        bind:value={formContent}
        placeholder="Write your thoughts here..."
        class="ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex min-h-37.5 w-full resize-none rounded-md border border-input bg-input/10 px-3 py-2 text-sm focus:bg-background focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
      ></textarea>
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={handleSave} disabled={formLoading} class="min-w-20">
      {formLoading ? "Saving..." : "Save"}
    </Button>
  {/snippet}
</ResponsiveModal>

{#if showDeleteDialog}
  <ResponsiveModal bind:open={showDeleteDialog} title="Delete Note">
    {#snippet description()}
      Are you sure you want to delete this note? This action cannot be undone.
    {/snippet}
    {#snippet footer()}
      <Button variant="outline" onclick={cancelDelete}>Cancel</Button>
      <Button variant="destructive" onclick={handleDelete}>Delete</Button>
    {/snippet}
  </ResponsiveModal>
{/if}

{#if showLogoutWarning}
  <ResponsiveModal bind:open={showLogoutWarning} title="Logout Warning">
    {#snippet description()}
      {#if logoutErrorMessage}
        Could not log out from the server.
        <br />
        <span class="text-muted-foreground">Reason: {logoutErrorMessage}</span>
      {:else}
        Could not log out from the server. Your local session has been cleared.
      {/if}
    {/snippet}
    {#snippet footer()}
      <Button onclick={acknowledgeLogoutWarning}>Continue to Login</Button>
    {/snippet}
  </ResponsiveModal>
{/if}
