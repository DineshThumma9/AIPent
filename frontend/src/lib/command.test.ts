import { describe, expect, it } from 'vitest'
import { curlBatchProbes } from './command'

const batchArgv = (batch: unknown) => [
  'mcp',
  'curl_request',
  JSON.stringify({ batch }),
]

describe('curlBatchProbes', () => {
  it('reads methods and paths from a batched curl_request', () => {
    const probes = curlBatchProbes(
      batchArgv([
        {
          follow_redirects: true,
          method: 'GET',
          url: 'http://host.docker.internal:3000/rest/products/search?q=apple',
        },
        {
          method: 'HEAD',
          url: 'http://host.docker.internal:3000/rest/user/login',
        },
      ]),
    )

    expect(probes).toEqual([
      {
        method: 'GET',
        path: '/rest/products/search?q=apple',
        url: 'http://host.docker.internal:3000/rest/products/search?q=apple',
      },
      {
        method: 'HEAD',
        path: '/rest/user/login',
        url: 'http://host.docker.internal:3000/rest/user/login',
      },
    ])
  })

  it('returns null for a single request or a non-curl command', () => {
    expect(
      curlBatchProbes([
        'mcp',
        'curl_request',
        JSON.stringify({ url: 'http://127.0.0.1:3000/', method: 'GET' }),
      ]),
    ).toBeNull()
    expect(curlBatchProbes(['nmap', '-sV', '127.0.0.1'])).toBeNull()
  })

  it('returns null for malformed or empty batches', () => {
    expect(curlBatchProbes(['mcp', 'curl_request', 'not-json'])).toBeNull()
    expect(curlBatchProbes(batchArgv([]))).toBeNull()
    expect(curlBatchProbes(batchArgv([{ method: 'GET' }]))).toBeNull()
  })
})
