/**
 * 父进程看门狗自测。
 *
 * 场景：DSH 被强杀（不是优雅退出）时，若边界代理留下，它会一直占着 127.0.0.1:3081，
 * 下次启动就撞 EADDRINUSE。这里断言的是**结果**：父进程死后，代理一定会在有界时间内消失。
 *
 * 实测补充（避免误读这些 PASS）：在本机上，代理总是在父进程退出后约 0.2–1 秒就消失，
 * 远快于看门狗 3 秒的周期；即使 `detached: true` 也一样。原因是调用方所在的 Windows
 * Job Object 会把整棵进程树一起收走 —— 也就是说代理自带的看门狗在这里**没有机会触发**，
 * 它的价值在于 `dsh web` 不经由这种 Job Object 启动时仍然成立。
 * 因此本探针无法证明看门狗生效，只能证明「不留残进程」这个要求被满足。
 */
import { spawn } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'

const PROXY = 'E:/dsh/dsh-tunnel-plugin/lib/edge-proxy.mjs'
const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
/** 允许的消失上限：看门狗一拍 3 秒，给到两拍余量。 */
const DEADLINE_MS = 9000

const failures = []
const check = (label, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === undefined || detail === '' ? '' : `  (${detail})`}`)
  if (!ok) failures.push(label)
}
const alive = (pid) => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/**
 * 起一个「生完就死」的临时父进程：拉起代理、确认代理已经在监听、报出代理 PID，然后退出。
 *
 * 刻意**不**在这里等父进程退出 —— 调用方需要能在父进程还活着的时候先确认代理是稳定的，
 * 所以把「父进程已退出」的 promise 一并交出去，由调用方决定什么时候等。
 *
 * @param stdoutMode - 代理 stdout 的处置方式；'pipe' 走宿主半的真实路径，'ignore' 只留看门狗。
 * @returns 代理 PID 与父进程退出信号。
 */
async function spawnAndOrphan(stdoutMode) {
  const script = `
const { spawn } = require('node:child_process')
const child = spawn(process.execPath, [
  '${PROXY}', '3081', '127.0.0.1:3080', '', '${DSH_HOME}',
], { stdio: ['ignore', ${JSON.stringify(stdoutMode)}, 'pipe'] })
let reported = false
function report() {
  if (reported) return
  reported = true
  process.stdout.write(String(child.pid))
  // 报出 PID 后仍停留一会儿，好让调用方在父进程存活期间观察代理。
  setTimeout(() => process.exit(0), 2500)
}
if (child.stdout) {
  let buffer = ''
  child.stdout.on('data', (chunk) => {
    buffer += chunk
    if (buffer.includes('TUNNEL_PROXY_READY')) report()
  })
} else {
  // stdout 被忽略时读不到就绪行，用固定延时等价代替。
  setTimeout(report, 1500)
}
setTimeout(() => { if (!reported) process.exit(2) }, 15000)
`
  const parent = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = ''
  parent.stdout.on('data', (chunk) => {
    stdout += chunk
  })
  const pid = await new Promise((resolve) => {
    const tick = setInterval(() => {
      const value = Number(stdout.trim())
      if (Number.isInteger(value) && value > 0) {
        clearInterval(tick)
        resolve(value)
      }
    }, 100)
  })
  return { pid, exited: new Promise((resolve) => parent.on('exit', resolve)) }
}

/** 等代理消失，返回实测耗时（毫秒）；超时返回 null。 */
async function waitUntilGone(pid) {
  const startedAt = Date.now()
  while (Date.now() - startedAt < DEADLINE_MS) {
    await new Promise((resolve) => setTimeout(resolve, 200))
    if (!alive(pid)) return Date.now() - startedAt
  }
  return null
}

console.log('--- 场景 1：stdout 走管道（宿主半的真实路径）---')
const piped = await spawnAndOrphan('pipe')
check('已拿到在监听中的代理 PID', Number.isInteger(piped.pid) && piped.pid > 0, String(piped.pid))
check('父进程未死时代理稳定存活', alive(piped.pid), '（应仍在监听 3081）')
await piped.exited
const pipedGone = await waitUntilGone(piped.pid)
check('父进程死后代理会消失', pipedGone !== null, pipedGone === null ? `超过 ${String(DEADLINE_MS)}ms 仍存活` : `${String(pipedGone)}ms`)

console.log('\n--- 场景 2：stdout 不建管道（只剩看门狗兜底）---')
const idle = await spawnAndOrphan('ignore')
check('已拿到代理 PID', Number.isInteger(idle.pid) && idle.pid > 0, String(idle.pid))
// 父进程仍存活期间反复确认，排除「代理自己会死」这一干扰因素。
let stableWhileParentAlive = true
for (let attempt = 0; attempt < 5 && stableWhileParentAlive; attempt += 1) {
  await new Promise((resolve) => setTimeout(resolve, 400))
  stableWhileParentAlive = alive(idle.pid)
}
check('父进程未死时代理不会自己退出', stableWhileParentAlive, '（持续观察约 2 秒）')
await idle.exited
const idleGone = await waitUntilGone(idle.pid)
check('看门狗让代理随父进程退出', idleGone !== null, idleGone === null ? `超过 ${String(DEADLINE_MS)}ms 仍存活` : `${String(idleGone)}ms`)

console.log(`\n${failures.length === 0 ? '全部通过' : `失败 ${String(failures.length)} 项: ${failures.join(', ')}`}`)
process.exit(failures.length === 0 ? 0 : 1)
