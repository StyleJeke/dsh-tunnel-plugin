/**
 * 启动图自测：确认客户端半已经被 DSH 列进 `__DSH_BOOT__`。
 *
 * 这一条与「插槽里有没有我的条目」是两件事：宿主半是 live reload 进来的，
 * 但浏览器要**刷新页面**才会把新的客户端插件包拉进启动图。所以判断标准是
 * DSH 现在提供的 index 里是否已经列出 dsh-tunnel/client.js —— 列了就说明
 * 用户只需 F5，不必重启 dsh web。
 */
import { createHmac, createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const AUTHORITY = '127.0.0.1:3080'
const BASE = `http://${AUTHORITY}`

const failures = []
const check = (label, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === undefined || detail === '' ? '' : `  (${detail})`}`)
  if (!ok) failures.push(label)
}

const credentials = join(DSH_HOME, '.credentials.yaml')
check('凭据文件存在', existsSync(credentials), credentials)
const secret = Buffer.from(
  readFileSync(credentials, 'utf8').match(/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/u)[1],
  'base64url',
)
const now = Date.now()
const body = Buffer.from(
  JSON.stringify({ version: 1, authority: AUTHORITY, issuedAt: now, expiresAt: now + 7 * 864e5 }),
  'utf8',
).toString('base64url')
const cookie = `dsh-auth-${createHash('sha256').update(AUTHORITY).digest('base64url')}=v1.${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`

const res = await fetch(`${BASE}/`, { headers: { cookie }, redirect: 'manual' })
check('能取到 index', res.status === 200, String(res.status))
const html = await res.text()

const boot = html.match(/__DSH_BOOT__"\] = (\{[\s\S]*?\});/u)?.[1] ?? html
check('index 含启动图', boot.includes('entries'))

check('启动图里列出了 dsh-tunnel 客户端包', boot.includes('dsh-tunnel'), boot.includes('dsh-tunnel') ? '' : '未列出，需要重启 dsh web 而不只是刷新页面')
check('对照：已装好的 whale-pet 也在启动图里', boot.includes('whale-pet'), boot.includes('whale-pet') ? '' : '（对照项缺失，说明判断方法本身有问题）')

const entry = boot.match(/\{"id":"dsh-tunnel"[^}]*\}/u)
if (entry !== null) console.log(`      ${entry[0]}`)

console.log(`\n${failures.length === 0 ? '全部通过' : `失败 ${String(failures.length)} 项: ${failures.join(', ')}`}`)
process.exit(failures.length === 0 ? 0 : 1)
