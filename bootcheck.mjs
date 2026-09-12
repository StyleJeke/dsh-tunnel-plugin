/**
 * 打印当前 DSH 提供的浏览器启动图里是否包含给定的包名。
 * 用法: node bootcheck.mjs <包名> [...]
 */
import { createHmac, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const AUTHORITY = '127.0.0.1:3080'
const secret = Buffer.from(
  readFileSync(`${DSH_HOME}/.credentials.yaml`, 'utf8').match(/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/u)[1],
  'base64url',
)
const now = Date.now()
const body = Buffer.from(JSON.stringify({ version: 1, authority: AUTHORITY, issuedAt: now, expiresAt: now + 864e5 }), 'utf8').toString('base64url')
const cookie = `dsh-auth-${createHash('sha256').update(AUTHORITY).digest('base64url')}=v1.${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`

const html = await (await fetch(`http://${AUTHORITY}/`, { headers: { cookie } })).text()
const entries = [...html.matchAll(/\{"id":"([^"]+)"/gu)].map((m) => m[1])
for (const name of process.argv.slice(2)) {
  console.log(`  ${entries.includes(name) ? '在  ' : '不在'}  ${name}`)
}
console.log(`  （启动图共 ${String(entries.length)} 项）`)
