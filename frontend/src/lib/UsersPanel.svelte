<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import { createEventDispatcher } from 'svelte'

  const dispatch = createEventDispatcher()
  function toast(msg, type = 'info') { dispatch('toast', { msg, type }) }

  // ── State ───────────────────────────────────────────────────────────────────
  export let proxyInfo = null

  let users = []
  let groups = []
  let loading = true

  // User form
  let userForm = { username: '', password: '', groups: [], note: '', enabled: true, regenToken: false }
  let editingUserId = null
  let showUserForm = false

  // Group form
  let groupForm = { name: '', description: '', patterns: [] }
  let patternInput = ''
  let editingGroupId = null
  let showGroupForm = false

  // VMess modal
  let vmessModal = null // { link, host, port, uuid, username }
  let vmessCopied = false

  // ── Data loading ────────────────────────────────────────────────────────────
  async function loadAll() {
    loading = true
    try {
      const [ur, gr] = await Promise.all([api.listUsers(), api.listGroups()])
      users = ur.users || []
      groups = gr.groups || []
    } catch (e) {
      toast('Failed to load: ' + e.message, 'error')
    }
    loading = false
  }

  onMount(loadAll)

  // ── User CRUD ────────────────────────────────────────────────────────────────
  function openCreateUser() {
    editingUserId = null
    userForm = { username: '', password: '', groups: [], note: '', enabled: true, regenToken: false }
    showUserForm = true
  }

  function openEditUser(u) {
    editingUserId = u.id
    userForm = {
      username: u.username,
      password: '',
      groups: [...(u.groups || [])],
      note: u.note || '',
      enabled: u.enabled,
      regenToken: false,
    }
    showUserForm = true
  }

  async function saveUser() {
    try {
      if (editingUserId) {
        await api.updateUser(editingUserId, {
          password: userForm.password || undefined,
          groups: userForm.groups,
          enabled: userForm.enabled,
          note: userForm.note,
          regen_token: userForm.regenToken,
        })
        toast('User updated', 'success')
      } else {
        await api.createUser({
          username: userForm.username,
          password: userForm.password,
          groups: userForm.groups,
          note: userForm.note,
        })
        toast('User created', 'success')
      }
      showUserForm = false
      await loadAll()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  async function deleteUser(u) {
    if (!confirm(`Delete user "${u.username}"?`)) return
    try {
      await api.deleteUser(u.id)
      toast('User deleted', 'success')
      await loadAll()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  // ── VMess export ────────────────────────────────────────────────────────────
  async function showVMess(u) {
    try {
      const data = await api.getVMessExport(u.id)
      vmessModal = data
      vmessCopied = false
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  async function copyVMess() {
    if (!vmessModal) return
    await navigator.clipboard.writeText(vmessModal.vmess_link)
    vmessCopied = true
    setTimeout(() => (vmessCopied = false), 2000)
  }

  // ── Group CRUD ───────────────────────────────────────────────────────────────
  function openCreateGroup() {
    editingGroupId = null
    groupForm = { name: '', description: '', patterns: [] }
    patternInput = ''
    showGroupForm = true
  }

  function openEditGroup(g) {
    editingGroupId = g.id
    groupForm = {
      name: g.name,
      description: g.description || '',
      patterns: [...(g.allowed_patterns || [])],
    }
    patternInput = ''
    showGroupForm = true
  }

  function addPattern() {
    const p = patternInput.trim()
    if (!p || groupForm.patterns.includes(p)) return
    try { new RegExp(p) } catch (e) { toast('Invalid regex: ' + e.message, 'error'); return }
    groupForm.patterns = [...groupForm.patterns, p]
    patternInput = ''
  }

  function removePattern(p) {
    groupForm.patterns = groupForm.patterns.filter(x => x !== p)
  }

  async function saveGroup() {
    try {
      if (editingGroupId) {
        await api.updateGroup(editingGroupId, {
          name: groupForm.name,
          description: groupForm.description,
          allowed_patterns: groupForm.patterns,
        })
        toast('Group updated', 'success')
      } else {
        await api.createGroup({
          name: groupForm.name,
          description: groupForm.description,
          allowed_patterns: groupForm.patterns,
        })
        toast('Group created', 'success')
      }
      showGroupForm = false
      await loadAll()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  async function deleteGroup(g) {
    if (!confirm(`Delete group "${g.name}"? Users in this group will lose its patterns.`)) return
    try {
      await api.deleteGroup(g.id)
      toast('Group deleted', 'success')
      await loadAll()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function groupName(id) {
    const g = groups.find(x => x.id === id)
    return g ? g.name : id
  }

  function toggleGroup(id) {
    if (userForm.groups.includes(id)) {
      userForm.groups = userForm.groups.filter(x => x !== id)
    } else {
      userForm.groups = [...userForm.groups, id]
    }
  }
</script>

<!-- ── Users section ─────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-header">
    <h3>👤 Proxy Users</h3>
    <button class="btn-primary" on:click={openCreateUser}>+ Add User</button>
  </div>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if users.length === 0}
    <p class="muted">No proxy users configured. All traffic uses the proxy without authentication.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Username</th>
          <th>Groups</th>
          <th>Status</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>
          {#each users as u (u.id)}
            <tr class:disabled-row={!u.enabled}>
              <td class="mono">{u.username}</td>
              <td>
                {#if u.groups && u.groups.length > 0}
                  {#each u.groups as gid}
                    <span class="tag">{groupName(gid)}</span>
                  {/each}
                {:else}
                  <span class="muted">unrestricted</span>
                {/if}
              </td>
              <td>
                <span class="badge-sm" class:green={u.enabled} class:red={!u.enabled}>
                  {u.enabled ? 'enabled' : 'disabled'}
                </span>
              </td>
              <td class="actions">
                <button class="btn-sm" on:click={() => showVMess(u)} title="Export VMess link">📲 VMess</button>
                <button class="btn-sm btn-edit" on:click={() => openEditUser(u)}>✏️ Edit</button>
                <button class="btn-sm btn-danger" on:click={() => deleteUser(u)}>🗑</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if proxyInfo?.auth_mode}
      <p class="hint">🔒 Proxy auth is active — clients must use <strong>username + token</strong> to connect.</p>
    {/if}
    {#if proxyInfo}
      <p class="hint">
        Per-user PAC: <code>{proxyInfo.host_ip}:8888/pac/&lt;username&gt;</code>
      </p>
    {/if}
  {/if}
</div>

<!-- ── Groups section ────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-header">
    <h3>🏷️ Proxy Groups</h3>
    <button class="btn-primary" on:click={openCreateGroup}>+ Add Group</button>
  </div>

  {#if groups.length === 0}
    <p class="muted">No groups yet. Groups let you restrict which domains a user can access via proxy (using regex patterns).</p>
  {:else}
    {#each groups as g (g.id)}
      <div class="group-card">
        <div class="group-header">
          <span class="group-name">{g.name}</span>
          {#if g.description}<span class="muted">&nbsp;— {g.description}</span>{/if}
          <div class="actions">
            <button class="btn-sm btn-edit" on:click={() => openEditGroup(g)}>✏️ Edit</button>
            <button class="btn-sm btn-danger" on:click={() => deleteGroup(g)}>🗑</button>
          </div>
        </div>
        <div class="patterns">
          {#if g.allowed_patterns && g.allowed_patterns.length > 0}
            {#each g.allowed_patterns as p}
              <code class="pattern">{p}</code>
            {/each}
          {:else}
            <span class="muted">No patterns — members can access all sites.</span>
          {/if}
        </div>
      </div>
    {/each}
  {/if}
</div>

<!-- ── User form modal ────────────────────────────────────────────────────── -->
{#if showUserForm}
  <div class="modal-overlay" on:click|self={() => (showUserForm = false)}>
    <div class="modal">
      <h3>{editingUserId ? 'Edit User' : 'Create User'}</h3>

      {#if !editingUserId}
        <div class="form-row">
          <label>Username</label>
          <input bind:value={userForm.username} placeholder="e.g. alice" />
        </div>
      {:else}
        <div class="form-row">
          <label>Username</label>
          <input value={userForm.username} disabled />
        </div>
      {/if}

      <div class="form-row">
        <label>{editingUserId ? 'New Password (leave blank to keep)' : 'Password (optional — token is always generated)'}</label>
        <input type="password" bind:value={userForm.password} placeholder="Leave blank to use token only" autocomplete="new-password" />
      </div>

      {#if editingUserId}
        <div class="form-row check-row">
          <label class="check-label">
            <input type="checkbox" bind:checked={userForm.regenToken} />
            Regenerate proxy token
          </label>
          <label class="check-label">
            <input type="checkbox" bind:checked={userForm.enabled} />
            Enabled
          </label>
        </div>
      {/if}

      {#if groups.length > 0}
        <div class="form-row">
          <label>Groups</label>
          <div class="group-checkboxes">
            {#each groups as g}
              <label class="check-label">
                <input type="checkbox" checked={userForm.groups.includes(g.id)}
                  on:change={() => toggleGroup(g.id)} />
                {g.name}
                {#if g.allowed_patterns?.length > 0}
                  <span class="muted">({g.allowed_patterns.length} patterns)</span>
                {:else}
                  <span class="muted">(unrestricted)</span>
                {/if}
              </label>
            {/each}
          </div>
        </div>
      {:else}
        <p class="hint">No groups defined. Create groups first to restrict which sites this user can access.</p>
      {/if}

      <div class="form-row">
        <label>Note (optional)</label>
        <input bind:value={userForm.note} placeholder="e.g. iPhone / dev laptop" />
      </div>

      <div class="modal-actions">
        <button class="btn-primary" on:click={saveUser}>💾 Save</button>
        <button on:click={() => (showUserForm = false)}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<!-- ── Group form modal ───────────────────────────────────────────────────── -->
{#if showGroupForm}
  <div class="modal-overlay" on:click|self={() => (showGroupForm = false)}>
    <div class="modal">
      <h3>{editingGroupId ? 'Edit Group' : 'Create Group'}</h3>

      <div class="form-row">
        <label>Group Name</label>
        <input bind:value={groupForm.name} placeholder="e.g. Engineering" />
      </div>

      <div class="form-row">
        <label>Description (optional)</label>
        <input bind:value={groupForm.description} placeholder="Short description" />
      </div>

      <div class="form-row">
        <label>Allowed Domain Patterns (regex)</label>
        <p class="hint" style="margin-bottom:8px">
          Leave empty = allow all sites. Add patterns to restrict to specific domains.<br>
          Examples: <code>.*\.corp\.example\.com</code> · <code>jenkins\..*</code> · <code>.*gitlab.*</code>
        </p>
        <div class="pattern-input-row">
          <input bind:value={patternInput}
            placeholder=".*\.example\.com"
            on:keydown={(e) => e.key === 'Enter' && addPattern()} />
          <button class="btn-sm btn-primary" on:click={addPattern}>Add</button>
        </div>
        <div class="pattern-list">
          {#each groupForm.patterns as p}
            <div class="pattern-row">
              <code>{p}</code>
              <button class="btn-sm btn-danger" on:click={() => removePattern(p)}>✕</button>
            </div>
          {/each}
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn-primary" on:click={saveGroup}>💾 Save</button>
        <button on:click={() => (showGroupForm = false)}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<!-- ── VMess modal ────────────────────────────────────────────────────────── -->
{#if vmessModal}
  <div class="modal-overlay" on:click|self={() => (vmessModal = null)}>
    <div class="modal vmess-modal">
      <h3>📲 VMess Link — {vmessModal.username}</h3>
      <p class="hint">Import this link in <strong>v2box</strong> / <strong>v2rayNG</strong> / <strong>Shadowrocket</strong>:</p>
      <p class="hint"><em>Add Server → Paste link / Scan QR code</em></p>

      <div class="vmess-box">
        <code class="vmess-link">{vmessModal.vmess_link}</code>
      </div>

      <div class="vmess-meta">
        <span>Host: <code>{vmessModal.host}:{vmessModal.port}</code></span>
        <span>UUID: <code>{vmessModal.uuid}</code></span>
      </div>

      <div class="modal-actions">
        <button class="btn-primary" on:click={copyVMess}>
          {vmessCopied ? '✅ Copied!' : '📋 Copy vmess:// link'}
        </button>
        <button on:click={() => (vmessModal = null)}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .muted { color: #64748b; font-size: 13px; }
  .hint { color: #94a3b8; font-size: 12px; margin-top: 8px; }
  .hint code { background: #0f172a; padding: 1px 5px; border-radius: 4px; }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 10px; font-size: 12px; color: #64748b; border-bottom: 1px solid #334155; }
  td { padding: 10px; border-bottom: 1px solid #1e293b; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .disabled-row td { opacity: 0.5; }
  .mono { font-family: monospace; }

  .tag { background: #1e3a5f; color: #93c5fd; font-size: 11px; padding: 2px 7px; border-radius: 4px; margin-right: 4px; }
  .badge-sm { font-size: 11px; padding: 2px 8px; border-radius: 4px; }
  .badge-sm.green { background: #14532d; color: #86efac; }
  .badge-sm.red   { background: #450a0a; color: #fca5a5; }

  .actions { display: flex; gap: 6px; }
  .btn-sm { font-size: 12px; padding: 4px 10px; background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
  .btn-sm:hover { background: #334155; }
  .btn-sm.btn-edit { background: #1e3a5f; color: #93c5fd; border-color: #1d4ed8; }
  .btn-sm.btn-danger { background: #450a0a; color: #fca5a5; border-color: #7f1d1d; }
  .btn-sm.btn-primary { background: #6366f1; color: #fff; border: none; }

  .group-card { border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; margin-bottom: 10px; }
  .group-header { display: flex; align-items: center; margin-bottom: 8px; }
  .group-name { font-weight: 600; color: #f1f5f9; }
  .group-header .actions { margin-left: auto; display: flex; gap: 6px; }
  .patterns { display: flex; flex-wrap: wrap; gap: 6px; }
  .pattern { background: #0f172a; border: 1px solid #334155; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: #a5b4fc; }

  /* Modal */
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.6);
    display: flex; align-items: center; justify-content: center;
    z-index: 100; padding: 16px;
  }
  .modal {
    background: #1e293b; border: 1px solid #334155; border-radius: 12px;
    padding: 24px; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto;
  }
  .modal h3 { margin-bottom: 18px; font-size: 16px; }
  .check-row { display: flex; gap: 20px; }
  .check-label { display: flex; align-items: center; gap: 6px; font-size: 13px; color: #cbd5e1; cursor: pointer; }
  .check-label input[type=checkbox] { width: auto; }
  .group-checkboxes { display: flex; flex-direction: column; gap: 8px; }
  .modal-actions { display: flex; gap: 10px; margin-top: 20px; }

  .pattern-input-row { display: flex; gap: 8px; }
  .pattern-input-row input { flex: 1; }
  .pattern-list { margin-top: 10px; display: flex; flex-direction: column; gap: 6px; }
  .pattern-row { display: flex; align-items: center; gap: 8px; }
  .pattern-row code { flex: 1; background: #0f172a; border: 1px solid #334155; padding: 4px 10px; border-radius: 4px; font-size: 12px; color: #a5b4fc; }

  .vmess-modal { max-width: 560px; }
  .vmess-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin: 12px 0; overflow-x: auto; }
  .vmess-link { font-size: 11px; word-break: break-all; color: #a5b4fc; }
  .vmess-meta { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: #94a3b8; }
  .vmess-meta code { color: #e2e8f0; }
</style>
