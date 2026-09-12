/**
 * DSH 内网穿透（公网隧道）—— 浏览器半。
 *
 * 这是按 DSH 客户端插件契约打包的模块：外层是 `__ModuleLoader__.load({id, factory})`
 * 包体，`require("react")` 取 React，最后导出 Cordis 插件要求的 `apply` / `inject`。
 *
 * 面板注册在 `settings.section`（设置里独立的一页），而不是会话内的某个卡片 ——
 * 隧道是部署级能力，与会话无关，放在设置里才找得到、也才留得住。
 *
 * 与宿主半之间不共享内存：全部经 `/dsh-tunnel/api/*` 三条自有路由通信。
 */
window.__ModuleLoader__.load({
	id: "dsh-tunnel",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		const React = require("react");

		//#region 常量与样式
		/** 本插件独占的路由前缀，与宿主半一致。 */
		const ROUTE_PREFIX = "/dsh-tunnel";
		/** 空闲时的状态轮询间隔。 */
		const POLL_MS = 4000;

		/**
		 * 全部样式集中在一个 <style> 标签里，由 apply 的 effect 持有并随插件卸载移除。
		 * 颜色一律优先取主题变量并带兜底值，明暗皮肤自动跟随。
		 */
		const CSS = `
.dt-root{max-width:660px;padding:2px 0;font-size:13px;line-height:1.6;}
.dt-title{font-size:15px;font-weight:600;color:var(--dsw-alias-label-primary,inherit);}
.dt-sub{margin-top:4px;margin-bottom:16px;font-size:12px;line-height:1.7;
  color:var(--dsw-alias-label-secondary,rgba(127,127,127,.95));}
.dt-head{display:flex;align-items:center;gap:8px;margin-bottom:10px;}
.dt-dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;background:var(--dsw-alias-label-secondary,#8a8a8a);}
.dt-dot-running{background:var(--dsw-alias-state-success-primary,#3fbf7f);}
.dt-dot-starting{background:var(--dsw-alias-state-warn-primary,#f0a03c);}
.dt-dot-error{background:var(--dsw-alias-state-error-primary,#ef6b6b);}
.dt-state{font-size:12px;font-weight:600;}
.dt-state-running{color:var(--dsw-alias-state-success-primary,#3fbf7f);}
.dt-state-starting{color:var(--dsw-alias-state-warn-primary,#f0a03c);}
.dt-state-error{color:var(--dsw-alias-state-error-primary,#ef6b6b);}
.dt-state-stopped{color:var(--dsw-alias-label-secondary,#8a8a8a);}
.dt-label{font-size:12px;color:var(--dsw-alias-label-secondary,rgba(127,127,127,.95));margin-bottom:4px;}
.dt-url{width:100%;box-sizing:border-box;padding:7px 9px;border-radius:6px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  color:var(--dsw-alias-label-primary,inherit);
  border:1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.4));
  background:rgba(127,127,127,.10);}
.dt-url:focus{outline:2px solid var(--dsw-alias-brand-primary,#7ba7f0);outline-offset:1px;}
.dt-actions{display:flex;gap:8px;margin:12px 0;}
.dt-btn{padding:5px 15px;border-radius:6px;font-size:12px;cursor:pointer;
  color:var(--dsw-alias-label-primary,inherit);
  border:1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.45));
  background:transparent;}
.dt-btn:hover:not(:disabled){background:rgba(127,127,127,.14);}
.dt-btn:disabled{opacity:.5;cursor:default;}
.dt-btn-primary{font-weight:600;color:#fff;border-color:var(--dsw-alias-brand-primary,#7ba7f0);
  background:var(--dsw-alias-brand-primary,#7ba7f0);}
.dt-btn-primary:hover:not(:disabled){filter:brightness(1.08);}
.dt-meta{margin:12px 0;padding:10px 12px;border-radius:8px;font-size:12px;
  border:1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.32));
  background:rgba(127,127,127,.06);}
.dt-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  color:var(--dsw-alias-label-primary,inherit);word-break:break-all;}
.dt-note{margin-top:6px;font-size:12px;color:var(--dsw-alias-label-secondary,rgba(127,127,127,.95));}
.dt-warn{padding:9px 11px;border-radius:8px;font-size:12px;line-height:1.7;
  border:1px solid var(--dsw-alias-state-warn-primary,rgba(240,160,60,.4));
  background:rgba(240,160,60,.12);color:var(--dsw-alias-label-primary,inherit);}
.dt-err{margin:12px 0;padding:9px 11px;border-radius:8px;font-size:12px;
  white-space:pre-wrap;word-break:break-word;
  border:1px solid var(--dsw-alias-state-error-primary,rgba(239,107,107,.4));
  background:rgba(239,107,107,.12);color:var(--dsw-alias-label-primary,inherit);}
.dt-alert{margin:12px 0;padding:9px 11px;border-radius:8px;font-size:12px;line-height:1.7;
  border:1px solid var(--dsw-alias-state-warn-primary,rgba(240,160,60,.55));
  background:rgba(240,160,60,.16);color:var(--dsw-alias-label-primary,inherit);}
.dt-hint{font-size:12px;color:var(--dsw-alias-label-secondary,rgba(127,127,127,.95));margin-bottom:10px;}
`;
		//#endregion

		//#region 面板
		/** 阶段 -> 人类可读文案。 */
		const PHASE_LABEL = {
			loading: "读取中",
			stopped: "已停止",
			starting: "启动中",
			running: "运行中",
			error: "出错",
		};

		/**
		 * 设置页里的隧道面板。
		 *
		 * 自己轮询宿主路由：面板只在设置页打开时挂载，轮询也就只在看得见的时候发生。
		 * @returns 面板元素。
		 */
		function Panel() {
			// 初值只需够渲染第一帧；真实状态由第一次轮询填入。autoStopHours 预置为 0，
			// 免得首帧把 undefined 渲染成「最长运行 undefined 小时」。
			const [view, setView] = React.useState({ phase: "loading", autoStopHours: 0, renewCount: 0 });
			const [busy, setBusy] = React.useState(null);

			React.useEffect(() => {
				let alive = true;
				const load = () => {
					fetch(`${ROUTE_PREFIX}/api/status`)
						.then((res) => res.json())
						.then((next) => {
							if (alive) setView(next);
						})
						.catch((error) => {
							if (alive) setView({ phase: "error", error: `无法读取隧道状态：${String(error?.message ?? error)}` });
						});
				};
				load();
				const timer = setInterval(load, POLL_MS);
				return () => {
					alive = false;
					clearInterval(timer);
				};
			}, []);

			/** 启停：请求可能要等几十秒（拉隧道），期间禁用按钮并靠轮询显示进度。 */
			const run = (action) => {
				setBusy(action);
				fetch(`${ROUTE_PREFIX}/api/${action}`)
					.then((res) => res.json())
					.then((next) => {
						setView(next);
						setBusy(null);
					})
					.catch((error) => {
						setBusy(null);
						setView({ phase: "error", error: String(error?.message ?? error) });
					});
			};

			const phase = view.phase ?? "loading";
			const running = phase === "running";
			const starting = phase === "starting";
			const accessUrl = view.accessUrl ?? null;

			const children = [];

			children.push(React.createElement("div", { className: "dt-root", key: "root" }, [
				React.createElement("div", { className: "dt-title", key: "title" }, "内网穿透（公网隧道）"),
				React.createElement("div", { className: "dt-sub", key: "sub" },
					"通过 Cloudflare 快速隧道把本机的 DSH 发布到公网，让其他电脑用浏览器访问。点“启动”后把访问链接发过去即可。"),

				React.createElement("div", { className: "dt-head", key: "head" }, [
					React.createElement("span", { className: `dt-dot dt-dot-${phase}`, key: "dot" }),
					React.createElement("span", { className: `dt-state dt-state-${phase}`, key: "state" },
						PHASE_LABEL[phase] ?? phase),
				]),

				accessUrl === null
					? React.createElement("div", { className: "dt-hint", key: "hint" },
						starting ? "正在建立隧道，通常 5 到 20 秒…" : "隧道未运行。点下面的“启动”按钮，这里会出现访问链接。")
					: React.createElement("div", { key: "url" }, [
						React.createElement("div", { className: "dt-label", key: "l" }, "访问链接（点一下可全选复制，发给另一台电脑）："),
						React.createElement("input", {
							key: "i",
							className: "dt-url",
							readOnly: true,
							value: accessUrl,
							onFocus: (event) => {
								try {
									event.target.select();
								} catch {
									/* 选区不可用不影响复制 */
								}
							},
						}),
					]),

				React.createElement("div", { className: "dt-actions", key: "actions" }, [
					React.createElement("button", {
						key: "start",
						type: "button",
						className: "dt-btn dt-btn-primary",
						disabled: busy !== null || running || starting,
						onClick: () => run("start"),
					}, busy === "start" ? "启动中…" : "启动"),
					React.createElement("button", {
						key: "stop",
						type: "button",
						className: "dt-btn",
						disabled: busy !== null || phase === "stopped" || phase === "loading",
						onClick: () => run("stop"),
					}, "停止"),
				]),

				view.error ? React.createElement("div", { className: "dt-err", key: "err" }, String(view.error)) : null,

				// 自动重连换掉了主机名时，旧链接立刻作废 —— 这件事必须显眼，不能只写在元信息里。
				view.linkChanged === true
					? React.createElement("div", { className: "dt-alert", key: "changed" }, [
						React.createElement("strong", { key: "t" }, "链接已更换："),
						"cloudflared 重启后 Cloudflare 分配了新域名，旧链接已失效，请改用上面的新链接（口令不变）。",
					])
					: null,

				React.createElement("div", { className: "dt-meta", key: "meta" }, [
					React.createElement("div", { className: "dt-mono", key: "m1" },
						`127.0.0.1:${String(view.proxyPort ?? 3081)}  ->  ${String(view.target ?? "127.0.0.1:3080")}`),
					React.createElement("div", { className: "dt-note", key: "m0" },
						view.namedHostname
							? `固定域名 ${String(view.namedHostname)} —— 重启后链接不变。`
							: "当前是临时链接（快速隧道）：Cloudflare 每次创建隧道都会分配新域名，进程一重启链接就会变。"),
					React.createElement("div", { className: "dt-note", key: "m2" },
						`隧道前方是一层边界代理：它重写 Host/Origin 以满足 DSH 的 /api 信任栅栏，并注入签名会话 cookie。${view.autoStopHours === 0 ? "不自动断开。" : `最长运行 ${String(view.autoStopHours)} 小时后自动断开。`}${view.autostart === true ? "已随 DSH 自动启动。" : ""}`),
					view.renewCount > 0
						? React.createElement("div", { className: "dt-note", key: "m4" }, `已自动重连 ${String(view.renewCount)} 次；只要 cloudflared 进程不重启，域名就不会变。`)
						: null,
					view.cloudflaredPath
						? React.createElement("div", { className: "dt-note", key: "m3" }, `cloudflared: ${String(view.cloudflaredPath)}`)
						: null,
				]),

				React.createElement("div", { className: "dt-warn", key: "warn" }, [
					React.createElement("strong", { key: "w" }, "安全提醒："),
					view.loginUser
						? `打开链接会先要求登录（账号 ${String(view.loginUser)}），登录后就能在这台电脑上执行任意命令，等同本机 DSH 的全部权限。请把口令当成这台机器的密码；连续输错会按来源 IP 逐次加倍锁定。`
						: "尚未设置登录账号密码，隧道会拒绝启动 —— 这是刻意的：唯一的门槛不能缺。请在本机插件目录下执行 node lib/set-credentials.mjs 后再启动。",
				]),
			]));

			return children;
		}
		//#endregion

		//#region 插件
		/** 需要槽位注册表。 */
		const inject = ["slots"];

		/**
		 * 把面板挂到设置里独立的一页。
		 *
		 * 为什么是 `settings.section` 而不是会话内的卡片：隧道是部署级、与会话无关的能力，
		 * 设置页是它唯一稳定且找得到的家；`id` 用一个自有值，不会顶掉任何官方页面。
		 * @param ctx - 客户端根上下文。
		 */
		function apply(ctx) {
			ctx.effect(() => {
				const tag = document.createElement("style");
				tag.textContent = CSS;
				document.head.append(tag);
				return () => tag.remove();
			});

			ctx.effect(() => ctx.slots.inject("settings.section", () => ctx.slots.register(
				{ name: "settings.section", id: "dsh-tunnel", order: 50, label: "内网穿透" },
				() => React.createElement(Panel),
			)));
		}
		//#endregion

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
