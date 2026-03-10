// Base URL — empty string = relative to current host (works both in dev+prod)
const BASE = ''

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  }
  if (body !== undefined) opts.body = JSON.stringify(body)
  const res = await fetch(BASE + path, opts)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || res.statusText)
  }
  return res.json()
}

export const api = {
  // ── Core ──────────────────────────────────────────────────────────────────
  status:     () => request('GET', '/api/status'),
  getConfig:  () => request('GET', '/api/config'),
  saveConfig: (data) => request('POST', '/api/config', data),
  connect:    (otp) => request('POST', '/api/vpn/connect', { otp }),
  disconnect: () => request('POST', '/api/vpn/disconnect'),
  logs:       () => request('GET', '/api/logs'),
  proxyInfo:  () => request('GET', '/api/proxy/info'),
  uploadCert: async (file) => {
    const form = new FormData()
    form.append('cert', file)
    const res = await fetch(BASE + '/api/certs/upload', { method: 'POST', body: form })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error(err.error || res.statusText)
    }
    return res.json()
  },

  // ── Auth ──────────────────────────────────────────────────────────────────
  authStatus:  () => request('GET', '/api/auth/status'),
  authLogout:  () => request('GET', '/auth/logout'),
  authLoginUrl: () => '/auth/login',

  // ── Users ─────────────────────────────────────────────────────────────────
  listUsers:      () => request('GET', '/api/users'),
  createUser:     (data) => request('POST', '/api/users', data),
  updateUser:     (id, data) => request('PUT', `/api/users/${id}`, data),
  deleteUser:     (id) => request('DELETE', `/api/users/${id}`),
  getVMessExport: (id, host) => {
    const q = host ? `?host=${encodeURIComponent(host)}` : ''
    return request('GET', `/api/users/${id}/vmess${q}`)
  },
  // Returns the raw JSON bytes of a v2ray client config (Content-Disposition: attachment)
  // Use getV2RayClientConfigUrl for direct <a href> downloads.
  getV2RayClientConfig: async (id, host, port) => {
    const p = new URLSearchParams()
    if (host) p.set('host', host)
    if (port) p.set('port', String(port))
    const q = p.toString() ? '?' + p.toString() : ''
    const res = await fetch(BASE + `/api/users/${id}/v2ray-config${q}`)
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error(err.error || res.statusText)
    }
    return res.text() // already pretty-printed JSON from the server
  },
  getV2RayClientConfigUrl: (id, host, port) => {
    const p = new URLSearchParams()
    if (host) p.set('host', host)
    if (port) p.set('port', String(port))
    const q = p.toString() ? '?' + p.toString() : ''
    return `${BASE}/api/users/${id}/v2ray-config${q}`
  },

  // ── Groups ────────────────────────────────────────────────────────────────
  listGroups:   () => request('GET', '/api/groups'),
  createGroup:  (data) => request('POST', '/api/groups', data),
  updateGroup:  (id, data) => request('PUT', `/api/groups/${id}`, data),
  deleteGroup:  (id) => request('DELETE', `/api/groups/${id}`),
}

