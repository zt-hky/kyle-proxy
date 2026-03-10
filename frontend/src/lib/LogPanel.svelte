<script>
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'

  let lines = []
  let autoScroll = true
  let logEl
  let pollInterval

  async function fetchLogs() {
    try {
      const data = await api.logs()
      lines = data.lines ?? []
      if (autoScroll && logEl) {
        setTimeout(() => logEl.scrollTo(0, logEl.scrollHeight), 50)
      }
    } catch {}
  }

  onMount(() => {
    fetchLogs()
    pollInterval = setInterval(fetchLogs, 2000)
  })
  onDestroy(() => clearInterval(pollInterval))

  function clear() { lines = [] }

  function colorLine(line) {
    if (/error|failed|fatal/i.test(line)) return 'err'
    if (/warn/i.test(line)) return 'warn'
    if (/connected|established|tunnel/i.test(line)) return 'ok'
    return ''
  }
</script>

<div class="card" style="margin-bottom:0">
  <div class="log-header">
    <h3>📋 VPN Logs</h3>
    <div class="log-controls">
      <label class="check-label">
        <input type="checkbox" bind:checked={autoScroll} />
        Auto-scroll
      </label>
      <button class="btn-secondary" on:click={clear} style="padding:4px 10px;font-size:12px">🗑 Clear</button>
    </div>
  </div>
  <div class="log-box" bind:this={logEl}>
    {#if lines.length === 0}
      <span class="empty">No logs yet — connect to VPN to see output.</span>
    {:else}
      {#each lines as line}
        <div class="line {colorLine(line)}">{line}</div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .log-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  .log-header h3 { margin-bottom: 0; }
  .log-controls { display: flex; align-items: center; gap: 10px; }
  .check-label { display: flex; align-items: center; gap: 5px; font-size: 12px; color: #94a3b8; cursor: pointer; }
  .check-label input { width: auto; }

  .log-box {
    background: #0a0f1e;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 10px;
    height: 420px;
    overflow-y: auto;
    font-family: 'Fira Code', 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.6;
    scrollbar-width: thin;
    scrollbar-color: #334155 transparent;
  }
  .line { white-space: pre-wrap; word-break: break-all; color: #94a3b8; }
  .line.err { color: #fca5a5; }
  .line.warn { color: #fde68a; }
  .line.ok { color: #86efac; }
  .empty { color: #334155; font-style: italic; }
</style>
