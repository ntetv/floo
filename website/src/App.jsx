import { useMemo, useState } from 'react'
import './App.css'

const navItems = [
  { key: 'dashboard', title: '状态总览', caption: '查看受管二进制与整体健康度' },
  { key: 'instances', title: '实例管理', caption: '切换实例、预览操作入口' },
  { key: 'logs', title: '日志查看', caption: '模拟 stdout / stderr 检查流' },
  { key: 'autostart', title: '启动项', caption: '预留开机自启接线位置' },
  { key: 'settings', title: '设置', caption: '预留目录、更新与偏好设置' },
]

const initialInstances = [
  {
    id: '49250',
    name: '办公室 RDP 客户端',
    kind: '客户端',
    binary: 'flooc.exe',
    state: '运行中',
    pid: '1494',
    autostart: '已启用',
    endpoint: '8.163.10.116:49251',
    mode: '模式 1 · 4 + 1 热备',
    target: '127.0.0.1:33889',
    config: '%LOCALAPPDATA%\\Floo\\configs\\49250.toml',
    stdout: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.client.49250.out.log',
    stderr: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.client.49250.err.log',
    note: '通过 import-client 导入，正在保持 4 条活跃隧道和 1 条热备隧道。',
    tags: ['已导入', 'Windows GUI 原型', '待接后端'],
    logs: {
      stdout: `[READY] Client ready.\n[CONFIG] Parallel tunnels: 4 active + 1 hot spare.\n[CLIENT] Local target 127.0.0.1:33889 is healthy.`,
      stderr: `[CLIENT] Connecting 4 parallel tunnels + 1 hot spare...\nEVENT CHECK_POINT|ROLE=CLIENT|MODE=1|ACTIVE=4|SPARE=1\n[GUI-SHELL] 当前为桌面壳原型，尚未接管真实进程。`,
    },
  },
  {
    id: '59252',
    name: '反向映射 SSH 服务端',
    kind: '服务端',
    binary: 'floos.exe',
    state: '已停止',
    pid: '-',
    autostart: '未启用',
    endpoint: '0.0.0.0:59251',
    mode: '反向监听',
    target: '0.0.0.0:59252 → 127.0.0.1:22',
    config: '%LOCALAPPDATA%\\Floo\\configs\\59252.toml',
    stdout: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.server.59252.out.log',
    stderr: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.server.59252.err.log',
    note: '等待重新绑定 reverse 端口，后续会接入 start/stop/restart。',
    tags: ['待启动', '反向服务', '待接后端'],
    logs: {
      stdout: `[IDLE] No listener process attached.\n[PLAN] Waiting for GUI action: start / enable-autostart.`,
      stderr: `[SERVER] Reverse port 59252 is reserved in prototype only.\n[GUI-SHELL] 这里展示的是日志布局，不会触发真实监听。`,
    },
  },
]

const addModes = [
  {
    key: 'client',
    label: '客户端',
    title: '添加客户端实例',
    description: '将导入后的客户端流转收敛到可视化列表中。',
    fields: [
      { name: 'server', label: '服务端地址', placeholder: '8.163.10.116:49251' },
      { name: 'target', label: '目标地址', placeholder: '127.0.0.1:33889' },
      { name: 'id', label: '实例 ID', placeholder: '49260' },
    ],
  },
  {
    key: 'server',
    label: '服务端',
    title: '添加服务端实例',
    description: '预演反向监听与服务名映射的添加流程。',
    fields: [
      { name: 'listen', label: '监听端口', placeholder: '59251' },
      { name: 'mapping', label: '映射名称', placeholder: 'ssh_59212' },
      { name: 'id', label: '实例 ID', placeholder: '59252' },
    ],
  },
]

const defaultImportPayload = '--preset=alpha-demo --server=8.163.10.116:63202 --client-id=63212 --client-target=127.0.0.1:57630'

const defaultAddForms = {
  client: {
    server: '8.163.10.116:49251',
    target: '127.0.0.1:33889',
    id: '49260',
  },
  server: {
    listen: '59251',
    mapping: 'ssh_59212',
    id: '59262',
  },
}

function extractValue(payload, pattern, fallback) {
  return payload.match(pattern)?.[1] ?? fallback
}

function buildImportPreview(payload) {
  return {
    server: extractValue(payload, /--server=([^\s]+)/, '8.163.10.116:63202'),
    clientId: extractValue(payload, /--client-id=([^\s]+)/, '63212'),
    mode: '模式 1 · 4 + 1 热备',
    target: extractValue(payload, /--client-target=([^\s]+)/, '127.0.0.1:57630'),
    preset: extractValue(payload, /--preset=([^\s]+)/, 'alpha-demo'),
  }
}

function buildInstancePaths(kind, id) {
  const role = kind === '客户端' ? 'client' : 'server'

  return {
    config: `%LOCALAPPDATA%\\Floo\\configs\\${id}.toml`,
    stdout: `%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.${role}.${id}.out.log`,
    stderr: `%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.${role}.${id}.err.log`,
  }
}

function createMockInstance({ id, name, kind, binary, state, pid, autostart, endpoint, mode, target, note, tags, logs }) {
  return {
    id,
    name,
    kind,
    binary,
    state,
    pid,
    autostart,
    endpoint,
    mode,
    target,
    note,
    tags,
    logs,
    ...buildInstancePaths(kind, id),
  }
}

function resolveValue(value, fallback) {
  return value || fallback
}

function resolveInstanceId(requestedId, existingIds, nextId) {
  if (!requestedId || existingIds.has(requestedId)) {
    return nextId
  }

  return requestedId
}

function formatClock(value = new Date()) {
  return value.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function buildImportedInstance(preview, id) {
  return createMockInstance({
    id,
    name: `导入客户端 ${id}`,
    kind: '客户端',
    binary: 'flooc.exe',
    state: '运行中',
    pid: String(2200 + Number(id.slice(-2))),
    autostart: '已启用',
    endpoint: preview.server,
    mode: preview.mode,
    target: preview.target,
    note: `由 GUI 壳模拟导入，预设 ${preview.preset} 已转换为实例卡片。`,
    tags: ['刚导入', '客户端', '模拟数据'],
    logs: {
      stdout: `[IMPORT] Preset ${preview.preset} attached.\n[READY] Client ${id} is visible in the prototype list.`,
      stderr: `[MOCK] import-client preview only.\n[SERVER] ${preview.server}\n[TARGET] ${preview.target}`,
    },
  })
}

function buildAddedInstance(mode, form, id) {
  if (mode === 'client') {
    return createMockInstance({
      id,
      name: `手动客户端 ${id}`,
      kind: '客户端',
      binary: 'flooc.exe',
      state: '已停止',
      pid: '-',
      autostart: '未启用',
      endpoint: resolveValue(form.server, '8.163.10.116:49251'),
      mode: '模式 1 · 手动添加',
      target: resolveValue(form.target, '127.0.0.1:33889'),
      note: '通过“添加实例”弹窗生成，待接入真实 create/import-client 逻辑。',
      tags: ['手动添加', '客户端', '待启动'],
      logs: {
        stdout: `[DRAFT] Client ${id} created in shell prototype.`,
        stderr: '[MOCK] Waiting for future backend wiring before launch.',
      },
    })
  }

  return createMockInstance({
    id,
    name: `手动服务端 ${id}`,
    kind: '服务端',
    binary: 'floos.exe',
    state: '已停止',
    pid: '-',
    autostart: '未启用',
    endpoint: `0.0.0.0:${resolveValue(form.listen, '59251')}`,
    mode: '反向监听',
    target: `${resolveValue(form.mapping, 'ssh_59212')} → 127.0.0.1:22`,
    note: '通过“添加实例”弹窗生成，便于先评审服务端布局与操作按钮。',
    tags: ['手动添加', '服务端', '待启动'],
    logs: {
      stdout: `[DRAFT] Server ${id} reserved for mapping ${resolveValue(form.mapping, 'ssh_59212')}.`,
      stderr: `[MOCK] Listener ${resolveValue(form.listen, '59251')} is not bound in prototype mode.`,
    },
  })
}

function App() {
  const [activeSection, setActiveSection] = useState('dashboard')
  const [instances, setInstances] = useState(initialInstances)
  const [selectedId, setSelectedId] = useState(initialInstances[0].id)
  const [showImport, setShowImport] = useState(false)
  const [showAdd, setShowAdd] = useState(false)
  const [showLogs, setShowLogs] = useState(false)
  const [logTab, setLogTab] = useState('stderr')
  const [addTab, setAddTab] = useState('client')
  const [importPayload, setImportPayload] = useState(defaultImportPayload)
  const [addForms, setAddForms] = useState(defaultAddForms)
  const [mockNotice, setMockNotice] = useState('当前为 GUI 壳测试入口：界面与状态为模拟数据，后续再接 flooc.exe / floos.exe。')
  const [lastRefreshAt, setLastRefreshAt] = useState(formatClock())

  const selected = useMemo(
    () => instances.find((item) => item.id === selectedId) ?? instances[0],
    [instances, selectedId],
  )
  const instanceIds = useMemo(() => new Set(instances.map((item) => item.id)), [instances])
  const nextId = useMemo(() => String(Math.max(...instances.map((item) => Number(item.id))) + 10), [instances])
  const importPreview = useMemo(() => buildImportPreview(importPayload), [importPayload])

  const addMode = addModes.find((item) => item.key === addTab) ?? addModes[0]
  const activeNav = navItems.find((item) => item.key === activeSection) ?? navItems[0]

  const summary = useMemo(() => {
    const runningCount = instances.filter((item) => item.state === '运行中').length
    const autostartCount = instances.filter((item) => item.autostart === '已启用').length
    const clientCount = instances.filter((item) => item.kind === '客户端').length

    return {
      total: instances.length,
      runningCount,
      clientCount,
      serverCount: instances.length - clientCount,
      autostartCount,
    }
  }, [instances])

  function pushNotice(message) {
    setMockNotice(message)
    setLastRefreshAt(formatClock())
  }

  function setSelectedPatch(update) {
    setInstances((current) =>
      current.map((item) => (item.id === selected.id ? update(item) : item)),
    )
  }

  function handleNavigation(nextKey) {
    setActiveSection(nextKey)

    if (nextKey === 'logs') {
      setShowLogs(true)
      pushNotice(`已切到日志视角，可继续检查实例 ${selected.id} 的 stdout / stderr 布局。`)
      return
    }

    if (nextKey === 'autostart') {
      pushNotice('开机启动仍是 mock 流程，后续会接 enable/disable autostart。')
      return
    }

    if (nextKey === 'settings') {
      pushNotice('设置页暂未展开；后续会放置受管目录、版本与更新策略。')
    }
  }

  function handleRefresh() {
    pushNotice('已完成一次模拟状态刷新；后续这里会串接 status / list。')
  }

  function handleInstanceAction(action) {
    if (!selected) {
      return
    }

    if (action === 'start') {
      if (selected.state === '运行中') {
        pushNotice(`实例 ${selected.id} 已在运行中，当前只演示按钮反馈。`)
        return
      }

      setSelectedPatch((item) => ({
        ...item,
        state: '运行中',
        pid: String(3000 + Number(item.id.slice(-2))),
        note: '通过 GUI 壳模拟启动成功，等待后续接入真实进程控制。',
      }))
      pushNotice(`已模拟启动实例 ${selected.id}。`)
      return
    }

    if (action === 'stop') {
      if (selected.state === '已停止') {
        pushNotice(`实例 ${selected.id} 当前已停止。`)
        return
      }

      setSelectedPatch((item) => ({
        ...item,
        state: '已停止',
        pid: '-',
        note: '通过 GUI 壳模拟停止成功，日志与配置路径保留。',
      }))
      pushNotice(`已模拟停止实例 ${selected.id}。`)
      return
    }

    if (action === 'restart') {
      setSelectedPatch((item) => ({
        ...item,
        state: '运行中',
        pid: String(4100 + Number(item.id.slice(-2))),
        note: '已完成一次模拟重启，用于验证按钮编排与详情刷新。',
      }))
      pushNotice(`已模拟重启实例 ${selected.id}。`)
      return
    }

    if (action === 'delete') {
      if (instances.length === 1) {
        pushNotice('至少保留一个实例卡片，避免原型界面落到空态。')
        return
      }

      const remaining = instances.filter((item) => item.id !== selected.id)
      setInstances(remaining)
      setSelectedId(remaining[0].id)
      pushNotice(`已从原型列表移除实例 ${selected.id}。`)
      return
    }

    if (action === 'enable-autostart') {
      setSelectedPatch((item) => ({ ...item, autostart: '已启用' }))
      pushNotice(`已为实例 ${selected.id} 模拟开启开机启动。`)
      return
    }

    if (action === 'disable-autostart') {
      setSelectedPatch((item) => ({ ...item, autostart: '未启用' }))
      pushNotice(`已为实例 ${selected.id} 模拟关闭开机启动。`)
    }
  }

  function handleImportSubmit() {
    const resolvedId = resolveInstanceId(importPreview.clientId, instanceIds, nextId)
    const imported = buildImportedInstance(importPreview, resolvedId)

    setInstances((current) => [imported, ...current])
    setSelectedId(imported.id)
    setShowImport(false)
    setActiveSection('instances')
    pushNotice(`已模拟导入客户端 ${imported.id}，可继续评审实例列表与详情联动。`)
  }

  function handleAddFormChange(field, value) {
    setAddForms((current) => ({
      ...current,
      [addTab]: {
        ...current[addTab],
        [field]: value,
      },
    }))
  }

  function handleAddSubmit() {
    const resolvedId = resolveInstanceId(addForms[addTab].id, instanceIds, nextId)
    const draft = buildAddedInstance(addTab, addForms[addTab], resolvedId)

    setInstances((current) => [draft, ...current])
    setSelectedId(draft.id)
    setShowAdd(false)
    setActiveSection('instances')
    pushNotice(`已模拟创建${draft.kind}实例 ${draft.id}。`)
  }

  return (
    <div className="shell-root">
      <aside className="side-panel">
        <div className="brand-block">
          <div className="brand-mark">F</div>
          <div>
            <div className="brand-title">Floo Win</div>
            <div className="brand-subtitle">Windows 管理器 GUI 壳原型</div>
          </div>
        </div>

        <div className="nav-section">
          {navItems.map((item) => (
            <button
              key={item.key}
              className={`nav-item ${item.key === activeSection ? 'nav-item-active' : ''}`}
              onClick={() => handleNavigation(item.key)}
            >
              <span>{item.title}</span>
              <small>{item.caption}</small>
            </button>
          ))}
        </div>

        <div className="rail-card">
          <div className="rail-card-title">发布入口</div>
          <div className="rail-card-value">floo-windows.exe</div>
          <div className="rail-card-copy">
            单文件 GUI 壳测试入口，方便在 Windows 上双击验证面板与弹窗布局。
          </div>
        </div>

        <div className="rail-card notice-card">
          <div className="rail-card-title">当前提示</div>
          <div className="notice-copy">{mockNotice}</div>
          <div className="notice-meta">最近刷新：{lastRefreshAt}</div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="topbar-copy">
            <span className="eyebrow">Floo Windows Manager Prototype</span>
            <h1>{activeNav.title}</h1>
            <p>
              先把 Windows 管理入口收敛成可双击、可评审的桌面壳。当前界面仅使用 mock 数据，后续再逐步接入
              <code>import-client</code>、<code>status</code>、<code>list</code>、<code>logs</code> 与实例控制命令。
            </p>
          </div>

          <div className="topbar-actions">
            <button className="ghost-button" onClick={handleRefresh}>
              刷新状态
            </button>
            <button className="secondary-button" onClick={() => setShowLogs(true)}>
              查看日志
            </button>
            <button className="primary-button" onClick={() => setShowImport(true)}>
              导入客户端
            </button>
          </div>
        </header>

        <section className="signal-strip">
          <span className="signal-pill">双击入口：floo-windows.exe</span>
          <span className="signal-pill muted">原型模式：未接真实进程</span>
          <span className="signal-pill muted">最后刷新：{lastRefreshAt}</span>
        </section>

        <section className="summary-grid">
          <article className="summary-card accent-violet">
            <span className="summary-label">实例总数</span>
            <strong>{summary.total}</strong>
            <span className="summary-hint">
              客户端 {summary.clientCount} / 服务端 {summary.serverCount}
            </span>
          </article>
          <article className="summary-card accent-amber">
            <span className="summary-label">运行中实例</span>
            <strong>{summary.runningCount}</strong>
            <span className="summary-hint">原型阶段用状态标签模拟 start / stop / restart。</span>
          </article>
          <article className="summary-card accent-emerald">
            <span className="summary-label">已启用自启动</span>
            <strong>{summary.autostartCount}</strong>
            <span className="summary-hint">后续对接 enable / disable autostart。</span>
          </article>
          <article className="summary-card accent-slate">
            <span className="summary-label">受管目录</span>
            <strong>%LOCALAPPDATA%</strong>
            <span className="summary-hint">统一承接 configs、logs 与 Windows 壳设置。</span>
          </article>
        </section>

        <section className="workspace-grid">
          <div className="table-card">
            <div className="section-head">
              <div>
                <span className="section-kicker">实例工作区</span>
                <h2>实例列表</h2>
                <p>点击行查看详情；所有操作按钮目前都提供 mock 反馈，方便先确认布局与操作流。</p>
              </div>
              <div className="section-actions">
                <button className="secondary-button" onClick={() => setShowAdd(true)}>
                  添加实例
                </button>
                <button className="secondary-button" onClick={() => setShowImport(true)}>
                  粘贴预设
                </button>
              </div>
            </div>

            <div className="table-shell">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>名称</th>
                    <th>类型</th>
                    <th>状态</th>
                    <th>PID</th>
                    <th>自启动</th>
                    <th>地址 / 服务端</th>
                  </tr>
                </thead>
                <tbody>
                  {instances.map((item) => (
                    <tr
                      key={item.id}
                      className={item.id === selectedId ? 'table-row-active' : ''}
                      onClick={() => setSelectedId(item.id)}
                    >
                      <td>{item.id}</td>
                      <td>
                        <div className="table-name">{item.name}</div>
                        <div className="table-subcopy">{item.binary}</div>
                      </td>
                      <td>{item.kind}</td>
                      <td>
                        <span className={`status-pill ${item.state === '运行中' ? 'running' : 'stopped'}`}>
                          {item.state}
                        </span>
                      </td>
                      <td>{item.pid}</td>
                      <td>{item.autostart}</td>
                      <td>{item.endpoint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="toolbar">
              <button className="toolbar-button" onClick={() => handleInstanceAction('start')}>
                启动
              </button>
              <button className="toolbar-button" onClick={() => handleInstanceAction('stop')}>
                停止
              </button>
              <button className="toolbar-button" onClick={() => handleInstanceAction('restart')}>
                重启
              </button>
              <button className="toolbar-button" onClick={() => setShowLogs(true)}>
                查看日志
              </button>
              <button className="toolbar-button" onClick={() => handleInstanceAction('enable-autostart')}>
                启用开机启动
              </button>
              <button className="toolbar-button" onClick={() => handleInstanceAction('disable-autostart')}>
                禁用开机启动
              </button>
              <button className="toolbar-button danger" onClick={() => handleInstanceAction('delete')}>
                删除
              </button>
            </div>
          </div>

          <aside className="detail-card">
            <div className="section-head compact">
              <div>
                <span className="section-kicker">当前选中</span>
                <h2>实例详情</h2>
                <p>
                  {selected.name} · {selected.id}
                </p>
              </div>
              <button className="ghost-button compact-button" onClick={() => setShowLogs(true)}>
                打开日志
              </button>
            </div>

            <div className="detail-tags">
              {selected.tags.map((tag) => (
                <span key={tag} className="detail-tag">
                  {tag}
                </span>
              ))}
            </div>

            <dl className="detail-list">
              <div>
                <dt>实例 ID</dt>
                <dd>{selected.id}</dd>
              </div>
              <div>
                <dt>类型</dt>
                <dd>{selected.kind}</dd>
              </div>
              <div>
                <dt>受管二进制</dt>
                <dd>{selected.binary}</dd>
              </div>
              <div>
                <dt>模式</dt>
                <dd>{selected.mode}</dd>
              </div>
              <div>
                <dt>目标 / 监听</dt>
                <dd>{selected.target}</dd>
              </div>
              <div>
                <dt>状态</dt>
                <dd>{selected.state}</dd>
              </div>
              <div>
                <dt>自启动</dt>
                <dd>{selected.autostart}</dd>
              </div>
              <div>
                <dt>配置文件</dt>
                <dd>{selected.config}</dd>
              </div>
              <div>
                <dt>标准输出日志</dt>
                <dd>{selected.stdout}</dd>
              </div>
              <div>
                <dt>标准错误日志</dt>
                <dd>{selected.stderr}</dd>
              </div>
            </dl>

            <div className="note-box">
              <span className="note-label">原型说明</span>
              <p>{selected.note}</p>
            </div>

            <div className="note-box muted-box">
              <span className="note-label">后续接线清单</span>
              <ul className="todo-list">
                <li>接入 `status` / `list` 生成真实实例视图</li>
                <li>接入 `start` / `stop` / `restart` / `logs`</li>
                <li>接入 `import-client` 与服务端 / 客户端创建逻辑</li>
                <li>接入 enable / disable autostart 与受管目录</li>
              </ul>
            </div>
          </aside>
        </section>
      </main>

      {showImport && (
        <div className="modal-backdrop" onClick={() => setShowImport(false)}>
          <div className="modal-card large" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h3>导入客户端</h3>
                <p>粘贴完整参数串，先验证解析预览、状态更新与实例卡片联动。</p>
              </div>
              <button className="close-button" onClick={() => setShowImport(false)}>
                关闭
              </button>
            </div>

            <label className="field-block">
              <span>导入参数</span>
              <textarea
                value={importPayload}
                onChange={(event) => setImportPayload(event.target.value)}
                rows={5}
              />
            </label>

            <div className="preview-card">
              <div className="preview-title">解析预览（原型模拟）</div>
              <div className="preview-grid">
                <div>
                  <span>服务端</span>
                  <strong>{importPreview.server}</strong>
                </div>
                <div>
                  <span>客户端 ID</span>
                  <strong>{importPreview.clientId}</strong>
                </div>
                <div>
                  <span>模式</span>
                  <strong>{importPreview.mode}</strong>
                </div>
                <div>
                  <span>目标地址</span>
                  <strong>{importPreview.target}</strong>
                </div>
              </div>
            </div>

            <div className="modal-actions">
              <button className="ghost-button" onClick={() => setShowImport(false)}>
                取消
              </button>
              <button className="primary-button" onClick={handleImportSubmit}>
                导入并启动
              </button>
            </div>
          </div>
        </div>
      )}

      {showAdd && (
        <div className="modal-backdrop" onClick={() => setShowAdd(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h3>添加实例</h3>
                <p>先确认服务端 / 客户端双入口与表单节奏，稍后再接真实创建逻辑。</p>
              </div>
              <button className="close-button" onClick={() => setShowAdd(false)}>
                关闭
              </button>
            </div>

            <div className="tab-row">
              {addModes.map((item) => (
                <button
                  key={item.key}
                  className={`tab-button ${item.key === addTab ? 'tab-active' : ''}`}
                  onClick={() => setAddTab(item.key)}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="form-stack">
              <div className="form-title">{addMode.title}</div>
              <p className="form-copy">{addMode.description}</p>
              {addMode.fields.map((field) => (
                <label key={field.name} className="field-block">
                  <span>{field.label}</span>
                  <input
                    placeholder={field.placeholder}
                    value={addForms[addTab][field.name] ?? ''}
                    onChange={(event) => handleAddFormChange(field.name, event.target.value)}
                  />
                </label>
              ))}
            </div>

            <div className="preview-card inline-card">
              <div className="preview-title">提交后会发生什么</div>
              <p>
                原型阶段会把新实例加入列表并联动详情卡片，不会真正写入配置文件或启动受管进程。
              </p>
            </div>

            <div className="modal-actions">
              <button className="ghost-button" onClick={() => setShowAdd(false)}>
                取消
              </button>
              <button className="primary-button" onClick={handleAddSubmit}>
                创建实例
              </button>
            </div>
          </div>
        </div>
      )}

      {showLogs && selected && (
        <div className="modal-backdrop" onClick={() => setShowLogs(false)}>
          <div className="modal-card large" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h3>查看日志</h3>
                <p>
                  {selected.name} · {selected.id} 的日志窗口原型。
                </p>
              </div>
              <button className="close-button" onClick={() => setShowLogs(false)}>
                关闭
              </button>
            </div>

            <div className="tab-row">
              <button className={`tab-button ${logTab === 'stderr' ? 'tab-active' : ''}`} onClick={() => setLogTab('stderr')}>
                标准错误
              </button>
              <button className={`tab-button ${logTab === 'stdout' ? 'tab-active' : ''}`} onClick={() => setLogTab('stdout')}>
                标准输出
              </button>
            </div>

            <div className="log-path-card">
              当前路径：{logTab === 'stderr' ? selected.stderr : selected.stdout}
            </div>

            <pre className="log-view">{selected.logs[logTab]}</pre>

            <div className="modal-actions">
              <button className="ghost-button" onClick={() => pushNotice('已模拟打开日志目录；后续会接系统文件管理器。')}>
                打开日志目录
              </button>
              <button className="primary-button" onClick={() => setShowLogs(false)}>
                完成
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
