export type HttpProbe = {
  method: string
  path: string
  url: string
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : null
}

function displayPath(url: string): string {
  try {
    const parsed = new URL(url)
    return `${parsed.pathname || '/'}${parsed.search}`
  } catch {
    return url
  }
}

/**
 * Read the readable requests out of a batched curl_request argv.
 *
 * The gateway argv is `["mcp", "curl_request", "{\"batch\": [...]}"]`. The
 * approval and step records only store that argv, so this is the one place
 * both the desk and the chat need to decode it. Anything unexpected falls
 * back to the raw command.
 */
export function curlBatchProbes(argv: string[]): HttpProbe[] | null {
  if (argv.length < 3 || argv[0] !== 'mcp' || argv[1] !== 'curl_request') {
    return null
  }

  let args: Record<string, unknown> | null
  try {
    args = asRecord(JSON.parse(argv[2]))
  } catch {
    return null
  }

  const batch = args?.batch
  if (!Array.isArray(batch) || batch.length === 0) return null

  const probes: HttpProbe[] = []
  for (const item of batch) {
    const entry = asRecord(item)
    if (!entry || typeof entry.url !== 'string') return null
    probes.push({
      method:
        typeof entry.method === 'string'
          ? entry.method.toUpperCase()
          : 'GET',
      path: displayPath(entry.url),
      url: entry.url,
    })
  }
  return probes
}
