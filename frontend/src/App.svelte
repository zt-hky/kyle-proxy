<script>
  import { onMount, onDestroy } from 'svelte'
  import { api } from './lib/api.js'
  import VpnPanel from './lib/VpnPanel.svelte'
  import ConfigPanel from './lib/ConfigPanel.svelte'
  import ProxyPanel from './lib/ProxyPanel.svelte'
  import LogPanel from './lib/LogPanel.svelte'

  let tab = 'dashboard'
  let status = { vpn: { state: 'disconnected' }, proxy: { running: false } }
  let proxyInfo = null
  let pollInterval = null
  let toast = null

  function showToast(msg, type = 'info') {
    toast = { msg, type }
    setTimeout(() => (toast = null), 3500)
  }

  async function poll() {
    try {
      status = await api.status()
    } catch (e) {
      // silently ignore poll failures
    }
  }

  onMount(async () => {
    await poll()
    try { proxyInfo = await api.proxyInfo() } catch {}
    pollInterval = setInterval(poll, 3000)
  })

  onDestroy(() => clearInterval(pollInterval))
</script>

<div class="app">
  <!-- ── Header ─────────────────────────────────────────────────── -->
  <header>
    <div class="logo">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>Kyle VPN Proxy</span>
    </div>
    <div class="status-badges">
      <span class="badge" class:green={status.vpn.state === 'connected'}
                          class:yellow={status.vpn.state === 'connecting' || status.vpn.state === 'disconnecting'}
                          class:red={status.vpn.state === 'error'}>
        VPN: {status.vpn.state}
      </span>
      <span class="badge" class:green={status.proxy.running}>
        Proxy: {status.proxy.running ? 'running' : 'stopped'}
      </span>
    </div>
  </header>

  <!-- ── Toast ──────────────────────────────────────────────────── -->
  {#if toast}
    <div class="toast {toast.type}">{toast.msg}</div>
  {/if}

  <!-- ── Tabs ───────────────────────────────────────────────────── -->
  <nav class="tabs">
    <button class:active={tab === 'dashboard'} on:click={() => (tab = 'dashboard')}>🏠 Dashboard</button>
    <button class:active={tab === 'config'} on:click={() => (tab = 'config')}>⚙️ Config</button>
    <button class:active={tab === 'proxy'} on:click={() => (tab = 'proxy')}>📡 Proxy</button>
    <button class:active={tab === 'logs'} on:click={() => (tab = 'logs')}>📋 Logs</button>
  </nav>

  <!-- ── Content ────────────────────────────────────────────────── -->
  <main>
    {#if tab === 'dashboard'}
      <VpnPanel {status} on:toast={(e) => showToast(e.detail.msg, e.detail.type)} />
    {:else if tab === 'config'}
      <ConfigPanel on:toast={(e) => showToast(e.detail.msg, e.detail.type)} />
    {:else if tab === 'proxy'}
      <ProxyPanel {proxyInfo} {status} />
    {:else if tab === 'logs'}
      <LogPanel />
    {/if}
  </main>
</div>

<style>
  :global(*) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) {
    background: #0f172a;
    color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    min-height: 100vh;
  }
  :global(input, select, textarea) {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #e2e8f0;
    padding: 8px 10px;
    width: 100%;
    font-size: 14px;
    outline: none;
    transition: border-color .2s;
  }
  :global(input:focus, select:focus) { border-color: #6366f1; }
  :global(button) {
    cursor: pointer;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    padding: 8px 16px;
    transition: opacity .15s, transform .1s;
  }
  :global(button:active) { transform: scale(.97); }
  :global(button:disabled) { opacity: .5; cursor: not-allowed; }
  :global(label) { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px; }
  :global(.card) {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 16px;
  }
  :global(.card h3) { font-size: 15px; font-weight: 600; margin-bottom: 14px; color: #f1f5f9; }
  :global(.form-row) { margin-bottom: 12px; }
  :global(.btn-primary) { background: #6366f1; color: #fff; }
  :global(.btn-primary:hover:not(:disabled)) { background: #4f46e5; }
  :global(.btn-danger) { background: #ef4444; color: #fff; }
  :global(.btn-danger:hover:not(:disabled)) { background: #dc2626; }
  :global(.btn-success) { background: #22c55e; color: #fff; }
  :global(.btn-success:hover:not(:disabled)) { background: #16a34a; }
  :global(.btn-secondary) { background: #334155; color: #e2e8f0; }
  :global(.btn-secondary:hover:not(:disabled)) { background: #475569; }

  .app { max-width: 760px; margin: 0 auto; padding: 0 12px 40px; }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 0;
    border-bottom: 1px solid #1e293b;
    margin-bottom: 16px;
  }
  .logo { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 700; color: #6366f1; }
  .status-badges { display: flex; gap: 8px; flex-wrap: wrap; }
  .badge {
    font-size: 11px;
    padding: 3px 10px;
    border-radius: 20px;
    background: #334155;
    color: #94a3b8;
    font-weight: 600;
    letter-spacing: .3px;
  }
  .badge.green { background: #14532d; color: #86efac; }
  .badge.yellow { background: #713f12; color: #fde68a; }
  .badge.red { background: #7f1d1d; color: #fca5a5; }

  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    background: #1e293b;
    padding: 4px;
    border-radius: 10px;
  }
  .tabs button {
    flex: 1;
    background: transparent;
    color: #94a3b8;
    padding: 8px 6px;
    border-radius: 7px;
    font-size: 13px;
    font-weight: 500;
  }
  .tabs button.active { background: #334155; color: #f1f5f9; }
  .tabs button:hover:not(.active) { color: #e2e8f0; }

  main { padding-bottom: 20px; }

  .toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 18px;
    border-radius: 8px;
    font-weight: 500;
    z-index: 999;
    animation: slideUp .25s ease;
    background: #334155;
    color: #e2e8f0;
    max-width: 320px;
  }
  .toast.success { background: #14532d; color: #86efac; }
  .toast.error { background: #7f1d1d; color: #fca5a5; }
  @keyframes slideUp {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }
</style>
