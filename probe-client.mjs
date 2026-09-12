/**
 * 客户端包体自测。
 *
 * 浏览器半是 `__ModuleLoader__.load({id, factory})` 包体，Node 里没有 window/document/React，
 * 所以这里把三者都换成探针：捕获 factory、用桩 React 真的把 Panel 渲染一次、
 * 用桩 slots 真的把注册走一遍。这样能在装进 profile 之前就抓到引用错误与契约错误。
 */
import { readFileSync } from 'node:fs'

const failures = []
const check = (label, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === undefined ? '' : `  (${detail})`}`)
  if (!ok) failures.push(label)
}

// --- 桩环境 -----------------------------------------------------------------
let captured = null
globalThis.window = { __ModuleLoader__: { load(def) { captured = def } } }

const styleTags = []
globalThis.document = {
  createElement() {
    return { textContent: '', remove() { styleTags.pop() } }
  },
  head: { append(tag) { styleTags.push(tag) } },
}

const fetchCalls = []
globalThis.fetch = (url) => {
  fetchCalls.push(String(url))
  return Promise.resolve({
    json: () => Promise.resolve({
      phase: 'running', error: null, publicUrl: 'https://x.trycloudflare.com',
      accessUrl: 'https://x.trycloudflare.com/?k=KEY', proxyPort: 3081, target: '127.0.0.1:3080',
      autoStopHours: 12, cloudflaredPath: 'C:/cf/cloudflared.exe', startedAt: 1, lastChange: 'ok',
    }),
  })
}

// 有状态的最小 hooks 桩：setView 必须真的生效，否则第二次渲染看不到运行态。
const hookState = []
let hookIndex = 0
const React = {
  createElement(type, props, ...children) { return { type, props: props ?? {}, children } },
  useState(initial) {
    const slot = hookIndex
    hookIndex += 1
    if (hookState[slot] === undefined) hookState[slot] = typeof initial === 'function' ? initial() : initial
    const set = (value) => {
      hookState[slot] = typeof value === 'function' ? value(hookState[slot]) : value
    }
    return [hookState[slot], set]
  },
  useEffect(effect) { effect() },
}

const ReactStub = React
const requireStub = (name) => {
  if (name === 'react') return ReactStub
  throw new Error(`unexpected require(${JSON.stringify(name)})`)
}

// --- 加载包体 ---------------------------------------------------------------
const source = readFileSync('E:/dsh/dsh-tunnel-plugin/lib/client.js', 'utf8')
// 包体引用 window，直接 eval 到当前全局即可。
new Function('window', 'document', source)(globalThis.window, globalThis.document)

check('包体调用 __ModuleLoader__.load', captured !== null)
check('模块 id 与包名一致', captured?.id === 'dsh-tunnel', captured?.id)
check('factory 是函数', typeof captured?.factory === 'function')

const mod = captured.factory(requireStub)
check('导出 apply', typeof mod.apply === 'function')
check('导出 inject = ["slots"]', Array.isArray(mod.inject) && mod.inject.length === 1 && mod.inject[0] === 'slots', JSON.stringify(mod.inject))

// --- 走一遍 apply -----------------------------------------------------------
const effects = []
const injectCalls = []
const registrations = []
const slots = {
  inject(key, callback) {
    injectCalls.push(key)
    return callback()
  },
  register(options, component) {
    registrations.push({ options, component })
    return () => {}
  },
}
const ctx = {
  effect(callback) {
    const disposer = callback()
    effects.push(disposer)
    return () => {}
  },
  slots,
}

let applyThrew = null
try {
  mod.apply(ctx)
} catch (error) {
  applyThrew = error
}
check('apply 不抛错', applyThrew === null, applyThrew?.message)
check('注入的槽位是 settings.section', injectCalls[0] === 'settings.section', JSON.stringify(injectCalls))
check('注册了 1 个条目', registrations.length === 1, String(registrations.length))

const opts = registrations[0]?.options ?? {}
check('id 是自己的 dsh-tunnel', opts.id === 'dsh-tunnel', JSON.stringify(opts))
check('order = 50', opts.order === 50)
check('label = 内网穿透', opts.label === '内网穿透')
check('注入了样式标签', styleTags.length === 1, String(styleTags.length))

// --- 真的渲染一次 Panel -----------------------------------------------------
// 每次渲染前重置 hook 游标，模拟 React 的一轮渲染。
function render() {
  hookIndex = 0
  return registrations[0].component().type()
}

let renderThrew = null
let firstTree = null
try {
  firstTree = render()
} catch (error) {
  renderThrew = error
}
check('Panel 渲染不抛错', renderThrew === null, renderThrew?.message)
check('渲染出元素树', Array.isArray(firstTree) && firstTree.length === 1)
check('初始态显示未运行提示', JSON.stringify(firstTree ?? []).includes('隧道未运行'))

// 等 useEffect 里那条 fetch 的 promise 链落地，再渲染一次看运行态。
await new Promise((resolve) => setTimeout(resolve, 30))

let secondThrew = null
let tree = null
try {
  tree = render()
} catch (error) {
  secondThrew = error
}
check('运行态渲染不抛错', secondThrew === null, secondThrew?.message)

const flat = JSON.stringify(tree ?? [])
check('面板含标题', flat.includes('内网穿透（公网隧道）'))
check('面板含安全提醒', flat.includes('安全提醒'))
check('运行态渲染出访问链接', flat.includes('trycloudflare.com'), flat.includes('trycloudflare.com') ? '' : flat.slice(0, 200))
check('运行态状态文案为运行中', flat.includes('运行中'))
check('渲染期间轮询了 status 路由', fetchCalls.some((u) => u.endsWith('/dsh-tunnel/api/status')), JSON.stringify(fetchCalls.slice(0, 2)))

console.log(`\n${failures.length === 0 ? '全部通过' : `失败 ${String(failures.length)} 项: ${failures.join(', ')}`}`)
process.exit(failures.length === 0 ? 0 : 1)
