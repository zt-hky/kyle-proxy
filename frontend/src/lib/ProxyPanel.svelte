<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  export let status = {}
  export let proxyInfo = null

  let copied = ''

  onMount(async () => {
    if (!proxyInfo) {
      try { proxyInfo = await api.proxyInfo() } catch {}
    }
  })

  function copy(text, key) {
    navigator.clipboard.writeText(text).then(() => {
      copied = key
      setTimeout(() => (copied = ''), 2000)
    })
  }

  $: vpnActive = status?.vpn?.state === 'connected'
</script>

<div class="card">
  <h3>📡 Proxy Connection Info</h3>

  {#if !vpnActive}
    <div class="warning-box">
      ⚠️  VPN is not connected. Proxy traffic will NOT go through the VPN tunnel.
    </div>
  {:else}
    <div class="success-box">
      ✅  VPN connected — proxy routes through the VPN tunnel.
    </div>
  {/if}

  {#if proxyInfo}
    <div class="info-grid">
      <div class="info-item">
        <span class="info-label">Server IP</span>
        <div class="copy-row">
          <code>{proxyInfo.host_ip}</code>
          <button class="btn-copy" on:click={() => copy(proxyInfo.host_ip, 'ip')}>
            {copied === 'ip' ? '✓' : '📋'}
          </button>
        </div>
      </div>

      <div class="info-item">
        <span class="info-label">HTTP Proxy</span>
        <div class="copy-row">
          <code>{proxyInfo.host_ip}:{proxyInfo.http_port}</code>
          <button class="btn-copy" on:click={() => copy(proxyInfo.host_ip + ':' + proxyInfo.http_port, 'http')}>
            {copied === 'http' ? '✓' : '📋'}
          </button>
        </div>
      </div>

      <div class="info-item">
        <span class="info-label">SOCKS5 Proxy</span>
        <div class="copy-row">
          <code>{proxyInfo.host_ip}:{proxyInfo.socks5_port}</code>
          <button class="btn-copy" on:click={() => copy(proxyInfo.host_ip + ':' + proxyInfo.socks5_port, 'socks')}>
            {copied === 'socks' ? '✓' : '📋'}
          </button>
        </div>
      </div>

      <div class="info-item">
        <span class="info-label">PAC URL (Auto-Config)</span>
        <div class="copy-row">
          <code>{proxyInfo.pac_url}</code>
          <button class="btn-copy" on:click={() => copy(proxyInfo.pac_url, 'pac')}>
            {copied === 'pac' ? '✓' : '📋'}
          </button>
        </div>
      </div>
    </div>
  {:else}
    <p style="color:#64748b">Loading proxy info…</p>
  {/if}
</div>

<!-- iPhone setup guide -->
<div class="card">
  <h3>📱 iPhone Setup Guide</h3>
  <ol class="steps">
    <li>
      <strong>Method 1 — Manual HTTP proxy</strong>
      <ul>
        <li>Settings → Wi-Fi → tap your network → Configure Proxy</li>
        <li>Select <b>Manual</b></li>
        <li>Server: <code>{proxyInfo?.host_ip ?? '&lt;server-ip&gt;'}</code></li>
        <li>Port: <code>{proxyInfo?.http_port ?? 8080}</code></li>
      </ul>
    </li>
    <li>
      <strong>Method 2 — Auto (PAC file, recommended)</strong>
      <ul>
        <li>Settings → Wi-Fi → tap your network → Configure Proxy</li>
        <li>Select <b>Auto</b></li>
        <li>URL: <code>{proxyInfo?.pac_url ?? 'http://&lt;server-ip&gt;:8888/pac'}</code></li>
      </ul>
    </li>
    <li>
      <strong>Method 3 — SOCKS5</strong>
      <ul>
        <li>Use an app like Shadowrocket or Quantumult X</li>
        <li>Add SOCKS5 server: <code>{proxyInfo?.host_ip ?? '&lt;server-ip&gt;'}</code>:<code>{proxyInfo?.socks5_port ?? 1080}</code></li>
      </ul>
    </li>
  </ol>
</div>

<style>
  .warning-box {
    background: #7c2d12;
    color: #fed7aa;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 16px;
    font-size: 13px;
  }
  .success-box {
    background: #14532d;
    color: #bbf7d0;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 16px;
    font-size: 13px;
  }
  .info-grid { display: grid; gap: 12px; }
  .info-item { }
  .info-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: .5px; display: block; margin-bottom: 4px; }
  .copy-row { display: flex; align-items: center; gap: 8px; }
  .copy-row code {
    flex: 1;
    background: #0f172a;
    padding: 6px 10px;
    border-radius: 5px;
    font-size: 13px;
    color: #a5b4fc;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .btn-copy {
    background: #334155;
    color: #94a3b8;
    padding: 5px 8px;
    border-radius: 5px;
    font-size: 13px;
    flex-shrink: 0;
  }
  .btn-copy:hover { background: #475569; color: #e2e8f0; }

  .steps { padding-left: 20px; line-height: 1.8; }
  .steps li { margin-bottom: 14px; }
  .steps ul { padding-left: 16px; margin-top: 4px; }
  .steps code { background: #0f172a; padding: 1px 6px; border-radius: 4px; color: #a5b4fc; font-size: 12px; }
</style>
