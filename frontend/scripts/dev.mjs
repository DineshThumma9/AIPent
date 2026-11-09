#!/usr/bin/env node
/**
 * Start the API and Vite together so `npm run dev` never leaves the browser
 * talking to a dead proxy on port 8010.
 *
 * - Reuses an API that is already healthy on 8010.
 * - Starts backend/.venv/bin/python (or AIPENT_PYTHON) when available.
 * - Starts Vite only after the API is reachable, or after a short timeout.
 */
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
import net from 'node:net'

const require = createRequire(import.meta.url)
const frontendDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const backendDir = resolve(frontendDir, '../backend')
const API_HOST = process.env.AIPENT_API_HOST ?? '127.0.0.1'
const API_PORT = Number(process.env.AIPENT_API_PORT ?? 8010)
const HEALTH_URL = `http://${API_HOST}:${API_PORT}/health`

let api = null
let vite = null
let shuttingDown = false

function log(message) {
  process.stdout.write(`\n[aipent] ${message}\n`)
}

function healthCheck(timeoutMs = 700) {
  return new Promise((resolveHealth) => {
    const request = http.get(HEALTH_URL, (response) => {
      response.resume()
      resolveHealth(response.statusCode === 200)
    })
    request.setTimeout(timeoutMs, () => {
      request.destroy()
      resolveHealth(false)
    })
    request.on('error', () => resolveHealth(false))
  })
}

async function portInUse() {
  return new Promise((resolveInUse) => {
    const socket = net.connect({ host: API_HOST, port: API_PORT })
    const done = (inUse) => {
      socket.destroy()
      resolveInUse(inUse)
    }
    socket.setTimeout(700, () => done(false))
    socket.on('connect', () => done(true))
    socket.on('error', () => done(false))
  })
}

async function waitForHealth(timeoutMs) {
  const deadline = Date.now() + timeoutMs
  process.stdout.write('[aipent] starting backend')
  while (Date.now() < deadline) {
    if (await healthCheck()) {
      process.stdout.write(' ready\n')
      return true
    }
    if (api && api.exitCode !== null) break
    process.stdout.write('.')
    await new Promise((done) => setTimeout(done, 350))
  }
  process.stdout.write('\n')
  return false
}

function pythonCommand() {
  if (process.env.AIPENT_PYTHON) return process.env.AIPENT_PYTHON
  const venv = resolve(backendDir, '.venv/bin/python')
  return existsSync(venv) ? venv : 'python3'
}

function stop(child) {
  if (child && !child.killed) {
    child.kill('SIGTERM')
  }
}

function shutdown(code = 0) {
  if (shuttingDown) return
  shuttingDown = true
  stop(vite)
  stop(api)
  process.exit(code)
}

async function startApi() {
  if (await healthCheck()) {
    log(`backend already running on ${API_HOST}:${API_PORT}`)
    return true
  }

  // Someone else owns the port but is not answering /health yet (a run in
  // progress, a reload mid-flight, etc.). Starting a second uvicorn would
  // only produce "address already in use" noise, so just wait it out.
  if (await portInUse()) {
    log(
      `port ${API_PORT} is already in use but /health is not answering yet; ` +
        'reusing it instead of starting a second backend.',
    )
    process.stdout.write('[aipent] waiting for backend')
    for (let i = 0; i < 8; i += 1) {
      if (await healthCheck()) {
        process.stdout.write(' ready\n')
        return true
      }
      process.stdout.write('.')
      await new Promise((done) => setTimeout(done, 500))
    }
    process.stdout.write('\n')
    log('backend still unresponsive; starting the web desk anyway.')
    return false
  }

  const python = pythonCommand()
  const env = { ...process.env }
  env.PYTHONPATH = [resolve(backendDir, 'src'), env.PYTHONPATH]
    .filter(Boolean)
    .join(':')

  api = spawn(
    python,
    [
      '-m',
      'uvicorn',
      'app.main:app',
      '--host',
      API_HOST,
      '--port',
      String(API_PORT),
    ],
    { cwd: backendDir, env, stdio: 'inherit' },
  )

  api.on('error', (error) => {
    log(`could not start backend: ${error.message}`)
    log('start it manually with: cd backend && uv run uvicorn app.main:app --port 8010')
  })

  api.on('exit', (code) => {
    if (shuttingDown) return
    if (code && code !== 0) {
      log(`backend exited with code ${code}. Continuing with the frontend only.`)
    }
  })

  const ready = await waitForHealth(30_000)
  if (!ready) {
    log('backend is still starting; Vite will keep retrying through the proxy.')
  }
  return ready
}

async function startVite() {
  // Vite's package `exports` no longer exposes ./bin/vite.js, so resolve the
  // package manifest (which is exported) and walk to the real entry point.
  const vitePkg = require.resolve('vite/package.json')
  const viteBin = resolve(dirname(vitePkg), 'bin/vite.js')
  vite = spawn(process.execPath, [viteBin, ...process.argv.slice(2)], {
    cwd: frontendDir,
    stdio: 'inherit',
  })
  vite.on('exit', (code) => shutdown(code ?? 0))
  vite.on('error', (error) => {
    log(`could not start Vite: ${error.message}`)
    shutdown(1)
  })
}

process.on('SIGINT', () => shutdown(0))
process.on('SIGTERM', () => shutdown(0))

await startApi()
await startVite()
