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
  status: () => request('GET', '/api/status'),
  getConfig: () => request('GET', '/api/config'),
  saveConfig: (data) => request('POST', '/api/config', data),
  connect: (otp) => request('POST', '/api/vpn/connect', { otp }),
  disconnect: () => request('POST', '/api/vpn/disconnect'),
  logs: () => request('GET', '/api/logs'),
  proxyInfo: () => request('GET', '/api/proxy/info'),
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
}
