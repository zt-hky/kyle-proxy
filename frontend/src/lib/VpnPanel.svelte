<script>
  import { createEventDispatcher } from 'svelte'
  import { api } from '../lib/api.js'

  export let status = { vpn: { state: 'disconnected' }, proxy: { running: false } }

  const dispatch = createEventDispatcher()

  let otp = ''
  let loading = false

  $: vpnState = status?.vpn?.state ?? 'disconnected'
  $: isConnected = vpnState === 'connected'
  $: isConnecting = vpnState === 'connecting' || vpnState === 'disconnecting'
  $: vpnIP = status?.vpn?.ip ?? ''
  $: vpnIface = status?.vpn?.interface ?? ''
  $: vpnSince = status?.vpn?.since ? new Date(status.vpn.since).toLocaleTimeString() : ''

  async function connect() {
    loading = true
    try {
      await api.connect(otp)
      otp = ''
      dispatch('toast', { msg: 'Connecting to VPN…', type: 'info' })
    } catch (e) {
      dispatch('toast', { msg: e.message, type: 'error' })
    } finally {
      loading = false
    }
  }

  async function disconnect() {
    loading = true
    try {
      await api.disconnect()
      dispatch('toast', { msg: 'Disconnecting…', type: 'info' })
    } catch (e) {
      dispatch('toast', { msg: e.message, type: 'error' })
    } finally {
      loading = false
    }
  }

  const stateColor = {
    connected: '#22c55e',
    connecting: '#f59e0b',
    disconnecting: '#f59e0b',
    disconnected: '#64748b',
    error: '#ef4444',
  }
</script>

<!-- VPN Status card -->
<div class="card">
  <h3>VPN Status</h3>
  <div class="status-row">
    <div class="dot" style="background:{stateColor[vpnState] ?? '#64748b'}"></div>
    <span class="state-label">{vpnState.charAt(0).toUpperCase() + vpnState.slice(1)}</span>
    {#if vpnIP}
      <span class="meta">· {vpnIP} on {vpnIface}</span>
    {/if}
    {#if vpnSince}
      <span class="meta">· since {vpnSince}</span>
    {/if}
  </div>

  {#if status?.vpn?.error}
    <p class="error-msg">{status.vpn.error}</p>
  {/if}

  {#if !isConnected && !isConnecting}
    <div class="otp-row">
      <div class="form-row" style="flex:1">
        <label for="otp">OTP / 2FA Token (if required)</label>
        <input id="otp" type="text" placeholder="123456" bind:value={otp} maxlength="12"
               on:keydown={(e) => e.key === 'Enter' && connect()} />
      </div>
      <button class="btn-success" on:click={connect} disabled={loading}>
        {loading ? '…' : '🔒 Connect'}
      </button>
    </div>
  {:else if isConnecting}
    <div class="connecting-anim">
      <span class="spinner"></span>
      <span>{vpnState === 'disconnecting' ? 'Disconnecting…' : 'Establishing tunnel…'}</span>
    </div>
  {:else}
    <button class="btn-danger" on:click={disconnect} disabled={loading}>
      {loading ? '…' : '🔓 Disconnect'}
    </button>
  {/if}
</div>

<!-- Proxy quick status -->
<div class="card">
  <h3>Proxy Service</h3>
  <div class="status-row">
    <div class="dot" style="background:{status?.proxy?.running ? '#22c55e' : '#ef4444'}"></div>
    <span class="state-label">{status?.proxy?.running ? 'Running' : 'Stopped'}</span>
    {#if status?.proxy?.running}
      <span class="meta">
        · HTTP :{status.proxy.http_port} · SOCKS5 :{status.proxy.socks5_port}
      </span>
    {/if}
  </div>
  {#if status?.proxy?.error}
    <p class="error-msg">{status.proxy.error}</p>
  {/if}
</div>

<style>
  .status-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
  }
  .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
    box-shadow: 0 0 6px currentColor;
  }
  .state-label { font-size: 16px; font-weight: 600; }
  .meta { color: #94a3b8; font-size: 13px; }
  .error-msg { color: #fca5a5; font-size: 13px; margin: -8px 0 12px; }

  .otp-row {
    display: flex;
    gap: 12px;
    align-items: flex-end;
  }
  .otp-row button { flex-shrink: 0; height: 37px; }

  .connecting-anim {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #f59e0b;
  }
  .spinner {
    display: inline-block;
    width: 16px; height: 16px;
    border: 2px solid #f59e0b;
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin .8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
