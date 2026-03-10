<script>
  import { onMount, createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'

  const dispatch = createEventDispatcher()

  let cfg = {
    portal: '', gateway: '', username: '', password: '',
    cert_file: '', trust_cert: false, extra_args: [],
    http_port: 8080, socks5_port: 1080,
  }
  let extraArgsStr = ''
  let hasPass = false
  let saving = false
  let certFile = null
  let uploadingCert = false

  onMount(async () => {
    try {
      const data = await api.getConfig()
      cfg = {
        portal: data.portal ?? '',
        gateway: data.gateway ?? '',
        username: data.username ?? '',
        password: '',
        cert_file: data.cert_file ?? '',
        trust_cert: data.trust_cert ?? false,
        extra_args: data.extra_args ?? [],
        http_port: data.http_port ?? 8080,
        socks5_port: data.socks5_port ?? 1080,
      }
      hasPass = data.has_password ?? false
      extraArgsStr = (data.extra_args ?? []).join(' ')
    } catch (e) {
      dispatch('toast', { msg: 'Failed to load config: ' + e.message, type: 'error' })
    }
  })

  async function save() {
    saving = true
    try {
      const payload = {
        ...cfg,
        extra_args: extraArgsStr.trim() ? extraArgsStr.trim().split(/\s+/) : [],
      }
      if (!payload.password) delete payload.password // don't overwrite with empty
      await api.saveConfig(payload)
      if (cfg.password) hasPass = true
      dispatch('toast', { msg: '✅ Configuration saved', type: 'success' })
    } catch (e) {
      dispatch('toast', { msg: 'Save failed: ' + e.message, type: 'error' })
    } finally {
      saving = false
    }
  }

  async function uploadCert() {
    if (!certFile) return
    uploadingCert = true
    try {
      const res = await api.uploadCert(certFile)
      cfg.cert_file = res.path
      if (res.warning) {
        dispatch('toast', { msg: '⚠️ ' + res.warning, type: 'info' })
      } else {
        dispatch('toast', { msg: '✅ Certificate installed', type: 'success' })
      }
    } catch (e) {
      dispatch('toast', { msg: 'Upload failed: ' + e.message, type: 'error' })
    } finally {
      uploadingCert = false
      certFile = null
    }
  }
</script>

<!-- VPN Connection Settings -->
<div class="card">
  <h3>🔗 GlobalProtect VPN</h3>

  <div class="form-row">
    <label for="portal">Portal URL *</label>
    <input id="portal" type="text" placeholder="vpn.company.com" bind:value={cfg.portal} />
  </div>
  <div class="form-row">
    <label for="gateway">Gateway (optional — auto-detected from portal)</label>
    <input id="gateway" type="text" placeholder="Leave blank to auto-select" bind:value={cfg.gateway} />
  </div>
  <div class="form-row">
    <label for="username">Username *</label>
    <input id="username" type="text" placeholder="user@company.com" bind:value={cfg.username} />
  </div>
  <div class="form-row">
    <label for="password">Password {hasPass ? '(saved — enter to update)' : '*'}</label>
    <input id="password" type="password"
           placeholder={hasPass ? '••••••••' : 'Enter password'}
           bind:value={cfg.password} />
  </div>
  <div class="form-row">
    <label for="extra">Extra openconnect args (space separated)</label>
    <input id="extra" type="text" placeholder="--no-dtls" bind:value={extraArgsStr} />
  </div>

  <div class="form-row trust-row">
    <label class="toggle-label">
      <input type="checkbox" bind:checked={cfg.trust_cert} />
      <span class="toggle-text">
        <strong>Skip TLS certificate check</strong>
        <span class="toggle-hint">Dùng khi VPN server có self-signed cert hoặc không validate được TLS (<code>--no-certificate-check</code>)</span>
      </span>
    </label>
    {#if cfg.trust_cert}
      <div class="warn-banner">⚠️ Đang tắt TLS verification — chỉ dùng với mạng nội bộ tin cậy</div>
    {/if}
  </div>
</div>

<!-- Proxy Port Settings -->
<div class="card">
  <h3>📡 Proxy Ports (v2ray)</h3>
  <div class="two-col">
    <div class="form-row">
      <label for="httpPort">HTTP Proxy Port</label>
      <input id="httpPort" type="number" min="1024" max="65535" bind:value={cfg.http_port} />
    </div>
    <div class="form-row">
      <label for="socksPort">SOCKS5 Proxy Port</label>
      <input id="socksPort" type="number" min="1024" max="65535" bind:value={cfg.socks5_port} />
    </div>
  </div>
</div>

<!-- Custom TLS Certificate -->
<div class="card">
  <h3>🔐 Custom CA Certificate (TLS)</h3>
  <p class="hint">Upload your corporate/internal CA cert (.crt/.pem) so gpclient trusts the VPN server.</p>
  {#if cfg.cert_file}
    <p class="current-cert">Current: <code>{cfg.cert_file}</code></p>
  {/if}
  <div class="cert-row">
    <input type="file" accept=".crt,.pem,.cer" on:change={(e) => certFile = e.target.files[0]} />
    <button class="btn-secondary" on:click={uploadCert}
            disabled={!certFile || uploadingCert}>
      {uploadingCert ? 'Uploading…' : '📤 Upload'}
    </button>
  </div>
</div>

<!-- Save button -->
<div class="save-row">
  <button class="btn-primary" on:click={save} disabled={saving} style="min-width:120px">
    {saving ? 'Saving…' : '💾 Save Config'}
  </button>
</div>

<style>
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .hint { color: #94a3b8; font-size: 13px; margin-bottom: 12px; }
  .current-cert { font-size: 12px; color: #64748b; margin-bottom: 8px; }
  .current-cert code { background: #0f172a; padding: 2px 6px; border-radius: 4px; }
  .cert-row { display: flex; gap: 10px; align-items: center; }
  .cert-row input[type=file] { flex: 1; padding: 6px; }
  .save-row { display: flex; justify-content: flex-end; }

  .trust-row { margin-top: 4px; }
  .toggle-label {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    cursor: pointer;
  }
  .toggle-label input[type=checkbox] {
    width: 16px; height: 16px;
    margin-top: 2px;
    flex-shrink: 0;
    accent-color: #f59e0b;
  }
  .toggle-text { display: flex; flex-direction: column; gap: 3px; }
  .toggle-hint { font-size: 12px; color: #64748b; }
  .toggle-hint code { background: #0f172a; padding: 1px 5px; border-radius: 3px; color: #fbbf24; }
  .warn-banner {
    margin-top: 8px;
    background: #78350f;
    color: #fde68a;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
  }
  @media (max-width: 480px) { .two-col { grid-template-columns: 1fr; } }
</style>
