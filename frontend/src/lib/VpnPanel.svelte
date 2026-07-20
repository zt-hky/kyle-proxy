<script>
  import { createEventDispatcher, onMount } from 'svelte'
  import { api } from '../lib/api.js'

  export let status = { vpn: { state: 'disconnected' } }

  const dispatch = createEventDispatcher()

  let otp = ''
  let nextOtp = ''
  let loading = false
  let otpLoading = false
  let configLoaded = false
  let hasOtpSecret = false
  let autoReconnect = false

  $: vpnState = status?.vpn?.state ?? 'disconnected'
  $: isConnected = vpnState === 'connected'
  $: isConnecting = vpnState === 'connecting' || vpnState === 'disconnecting'
  $: awaitingOtp = Boolean(status?.vpn?.awaiting_otp)
  $: otpPromptCount = status?.vpn?.otp_prompt_count ?? 0
  $: vpnPhase = status?.vpn?.phase ?? ''
  $: vpnDetail = status?.vpn?.detail ?? ''
  $: vpnLastLog = status?.vpn?.last_log ?? ''
  $: vpnIP = status?.vpn?.ip ?? ''
  $: vpnIface = status?.vpn?.interface ?? ''
  $: vpnSince = status?.vpn?.since ? new Date(status.vpn.since).toLocaleTimeString() : ''
  $: autoOtpActive = Boolean(status?.vpn?.auto_otp)
  $: reconnectAttempt = status?.vpn?.reconnect_attempt ?? 0
  $: canAutoReconnect = hasOtpSecret

  onMount(loadConfig)

  async function loadConfig() {
    try {
      const cfg = await api.getConfig()
      hasOtpSecret = Boolean(cfg.has_otp_secret)
      autoReconnect = Boolean(cfg.auto_reconnect && cfg.has_otp_secret)
    } catch (e) {
      dispatch('toast', { msg: 'Failed to load VPN config: ' + e.message, type: 'error' })
    } finally {
      configLoaded = true
    }
  }

  async function connect() {
    loading = true
    try {
      await api.connect(hasOtpSecret ? '' : otp, '', autoReconnect && hasOtpSecret)
      otp = ''
      dispatch('toast', { msg: 'Connecting to VPN…', type: 'info' })
    } catch (e) {
      dispatch('toast', { msg: e.message, type: 'error' })
    } finally {
      loading = false
    }
  }

  async function submitOtp() {
    otpLoading = true
    try {
      await api.submitOtp(nextOtp)
      nextOtp = ''
      dispatch('toast', { msg: 'OTP submitted…', type: 'info' })
    } catch (e) {
      dispatch('toast', { msg: e.message, type: 'error' })
    } finally {
      otpLoading = false
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

  {#if vpnPhase || vpnDetail || (isConnecting && vpnLastLog)}
    <div class="phase-box">
      {#if vpnPhase}
        <div class="phase-row">
          <span class="phase-label">Current step</span>
          <span class="phase-value">{vpnPhase}</span>
        </div>
      {/if}
      {#if vpnDetail}
        <div class="phase-detail">{vpnDetail}</div>
      {/if}
      {#if autoOtpActive}
        <div class="phase-detail subtle">TOTP automation enabled</div>
      {/if}
      {#if reconnectAttempt}
        <div class="phase-detail subtle">Reconnect attempt #{reconnectAttempt}</div>
      {/if}
      {#if isConnecting && vpnLastLog}
        <div class="last-log">{vpnLastLog}</div>
      {/if}
    </div>
  {/if}

  {#if !isConnected && !isConnecting}
    <div class="otp-row">
      {#if hasOtpSecret}
        <div class="secret-box">
          <span class="secret-title">Saved TOTP key</span>
          <label class="inline-check">
            <input type="checkbox" bind:checked={autoReconnect} disabled={!canAutoReconnect} />
            <span>Auto reconnect</span>
          </label>
        </div>
      {:else}
        <div class="form-row" style="flex:1">
          <label for="otp">OTP / 2FA Token *</label>
          <input id="otp" type="text" placeholder="123456" bind:value={otp} maxlength="32"
                 on:keydown={(e) => e.key === 'Enter' && otp.trim() && connect()} />
        </div>
      {/if}
      <button class="btn-success" on:click={connect} disabled={loading || !configLoaded || (!hasOtpSecret && !otp.trim())}>
        {loading ? '…' : '🔒 Connect'}
      </button>
    </div>
  {:else if isConnecting}
    {#if awaitingOtp}
      <div class="otp-row">
        <div class="form-row" style="flex:1">
          <label for="next-otp">Fresh OTP #{otpPromptCount}</label>
          <input id="next-otp" type="text" placeholder="wait for the next OTP code" bind:value={nextOtp} maxlength="32"
                 on:keydown={(e) => e.key === 'Enter' && submitOtp()} />
        </div>
        <button class="btn-success" on:click={submitOtp} disabled={otpLoading || !nextOtp.trim()}>
          {otpLoading ? '…' : 'Submit OTP'}
        </button>
      </div>
      <button class="btn-secondary disconnect-small" on:click={disconnect} disabled={loading}>
        Cancel
      </button>
    {:else}
      <div class="connecting-anim">
        <span class="spinner"></span>
        <span>{vpnState === 'disconnecting' ? 'Disconnecting…' : (vpnDetail || 'Establishing tunnel…')}</span>
      </div>
      <button class="btn-secondary disconnect-small" on:click={disconnect} disabled={loading}>
        Cancel
      </button>
    {/if}
  {:else}
    <button class="btn-danger" on:click={disconnect} disabled={loading}>
      {loading ? '…' : '🔓 Disconnect'}
    </button>
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

  .phase-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 10px;
    margin: -4px 0 14px;
  }
  .phase-row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 6px;
  }
  .phase-label,
  .last-log {
    color: #94a3b8;
    font-size: 12px;
  }
  .phase-value {
    color: #fde68a;
    font-size: 12px;
    font-weight: 700;
  }
  .phase-detail {
    color: #e2e8f0;
    font-size: 13px;
    margin-bottom: 6px;
  }
  .phase-detail.subtle { color: #94a3b8; }
  .last-log {
    font-family: 'Fira Code', 'Cascadia Code', monospace;
    overflow-wrap: anywhere;
  }

  .otp-row {
    display: flex;
    gap: 12px;
    align-items: flex-end;
  }
  .otp-row button { flex-shrink: 0; height: 37px; }
  .secret-box {
    flex: 1;
    min-height: 37px;
    border: 1px solid #334155;
    border-radius: 6px;
    background: #0f172a;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 10px;
  }
  .secret-title {
    color: #bbf7d0;
    font-size: 13px;
    font-weight: 600;
  }
  .inline-check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #cbd5e1;
    font-size: 12px;
    margin: 0;
    white-space: nowrap;
  }
  .inline-check input {
    width: 14px;
    height: 14px;
    accent-color: #22c55e;
  }

  @media (max-width: 640px) {
    .otp-row {
      align-items: stretch;
      flex-direction: column;
    }
    .otp-row button {
      width: 100%;
    }
    .secret-box {
      align-items: flex-start;
      flex-direction: column;
    }
  }

  .connecting-anim {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #f59e0b;
  }
  .disconnect-small {
    margin-top: 12px;
    padding: 6px 12px;
    font-size: 12px;
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
