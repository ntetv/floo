import { useMemo, useState } from 'react'
import './App.css'

const instances = [
  {
    id: '49250',
    kind: '客户端',
    state: '运行中',
    pid: '1494',
    autostart: '已启用',
    server: '8.163.10.116:49251',
    mode: '模式 1',
    target: '127.0.0.1:33889',
    config: '%LOCALAPPDATA%\\Floo\\configs\\49250.toml',
    stdout: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.client.49250.out.log',
    stderr: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.client.49250.err.log',
    note: '通过 import-client 导入，正在保持 4 + 1 热备隧道。',
  },
  {
    id: '59252',
    kind: '服务端',
    state: '已停止',
    pid: '-',
    autostart: '未启用',
    server: '0.0.0.0:59251',
    mode: '模式 1',
    target: '反向监听 0.0.0.0:59252',
    config: '%LOCALAPPDATA%\\Floo\\configs\\59252.toml',
    stdout: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.server.59252.out.log',
    stderr: '%LOCALAPPDATA%\\Floo\\logs\\com.ntetv.floo.server.59252.err.log',
    note: '等待重新绑定 reverse 端口。',
  },
]

const addModes = [
  {
    key: 'client',
    title: '添加客户端实例',
    fields: [
      { label: '服务端地址', placeholder: '8.163.10.116:49251' },
      { label: '目标地址', placeholder: '127.0.0.1:33889' },
      { label: '实例 ID', placeholder: '49250' },
    ],
  },
  {
    key: 'server',
    title: '添加服务端实例',
    fields: [
      { label: '监听端口', placeholder: '59251' },
      { label: '映射名称', placeholder: 'ssh_59212' },
      { label: '实例 ID', placeholder: '59252' },
    ],
  },
]

const logsMock = {
  stdout: `[READY] Client ready.\n[CONFIG] Parallel Tunnels: 4 (auto)\n[CLIENT] All tunnel threads started.`,
  stderr: `[CLIENT] Connecting 4 parallel tunnels + 1 hot spare...\nEVENT CHECK_POINT|ROLE=CLIENT|MODE=1|ACTIVE=4|SPARE=1`,
}

function App() {
  const [selectedId, setSelectedId] = useState(instances[0].id)
  const [showImport, setShowImport] = useState(false)
  const [showAdd, setShowAdd] = useState(false)
  const [showLogs, setShowLogs] = useState(false)
  const [logTab, setLogTab] = useState('stderr')
  const [addTab, setAddTab] = useState('client')
  const [importPayload, setImportPayload] = useState('--preset=... --client-target=127.0.0.1:57630')

  const selected = useMemo(
    () => instances.find((item) => item.id === selectedId) ?? instances[0],
    [selectedId],
  )

  const addMode = addModes.find((item) => item.key === addTab) ?? addModes[0]

  return (
    <div className="shell-root">
      <aside className="side-panel">
        <div className="brand-block">
          <div className="brand-mark">F</div>
          <div>
            <div className="brand-title">Floo Win</div>
            <div className="brand-subtitle">Windows 客户端管理面板</div>
          </div>
        </div>

        <div className="nav-section">
          <button className="nav-item nav-item-active">状态总览</button>
          <button className="nav-item">实例管理</button>
          <button className="nav-item">日志查看</button>
          <button className="nav-item">启动项</button>
          <button className="nav-item">设置</button>
        </div>

        <div className="release-card">
          <div className="release-title">当前渠道</div>
          <div className="release-value">latest release</div>
          <div className="release-meta">单 exe GUI 壳原型（未接后端）</div>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <h1>状态面板</h1>
            <p>统一查看 Floo Windows 端实例状态、导入客户端与自启动配置。</p>
          </div>
          <div className="topbar-actions">
            <button className="ghost-button">刷新状态</button>
            <button className="primary-button" onClick={() => setShowImport(true)}>
              导入客户端
            </button>
          </div>
        </header>

        <section className="summary-grid">
          <article className="summary-card accent-purple">
            <span className="summary-label">实例总数</span>
            <strong>2</strong>
            <span className="summary-hint">服务端 1 / 客户端 1</span>
          </article>
          <article className="summary-card accent-orange">
            <span className="summary-label">受管二进制</span>
            <strong>flooc.exe</strong>
            <span className="summary-hint">版本 0.1.6（示意）</span>
          </article>
          <article className="summary-card accent-green">
            <span className="summary-label">默认隧道策略</span>
            <strong>4 + 1</strong>
            <span className="summary-hint">auto 模式默认 4 active + 1 hot spare</span>
          </article>
        </section>

        <section className="workspace-grid">
          <div className="table-card">
            <div className="section-head">
              <div>
                <h2>实例列表</h2>
                <p>点击行查看详情，后续这里将接入真实状态刷新。</p>
              </div>
              <div className="section-actions">
                <button className="secondary-button" onClick={() => setShowAdd(true)}>
                  添加实例
                </button>
                <button className="secondary-button" onClick={() => setShowLogs(true)}>
                  查看日志
                </button>
              </div>
            </div>

            <div className="table-shell">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
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
                      <td>{item.kind}</td>
                      <td>
                        <span className={`status-pill ${item.state === '运行中' ? 'running' : 'stopped'}`}>
                          {item.state}
                        </span>
                      </td>
                      <td>{item.pid}</td>
                      <td>{item.autostart}</td>
                      <td>{item.server}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="toolbar">
              <button className="toolbar-button">启动</button>
              <button className="toolbar-button">停止</button>
              <button className="toolbar-button">重启</button>
              <button className="toolbar-button danger">删除</button>
              <button className="toolbar-button">启用开机启动</button>
              <button className="toolbar-button">禁用开机启动</button>
            </div>
          </div>

          <aside className="detail-card">
            <div className="section-head compact">
              <div>
                <h2>实例详情</h2>
                <p>当前选中实例：{selected.id}</p>
              </div>
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
              <span className="note-label">备注</span>
              <p>{selected.note}</p>
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
                <p>粘贴完整参数串，后续将自动解析并执行导入。</p>
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
              <div className="preview-title">解析预览（静态演示）</div>
              <div className="preview-grid">
                <div><span>服务端</span><strong>8.163.10.116:63202</strong></div>
                <div><span>客户端 ID</span><strong>63212</strong></div>
                <div><span>模式</span><strong>模式 1</strong></div>
                <div><span>目标地址</span><strong>127.0.0.1:57630</strong></div>
              </div>
            </div>

            <div className="modal-actions">
              <button className="ghost-button" onClick={() => setShowImport(false)}>
                取消
              </button>
              <button className="primary-button">导入并启动</button>
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
                <p>先确认界面交互，后续再接真实创建逻辑。</p>
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
                  {item.key === 'client' ? '客户端' : '服务端'}
                </button>
              ))}
            </div>

            <div className="form-stack">
              <div className="form-title">{addMode.title}</div>
              {addMode.fields.map((field) => (
                <label key={field.label} className="field-block">
                  <span>{field.label}</span>
                  <input placeholder={field.placeholder} />
                </label>
              ))}
            </div>

            <div className="modal-actions">
              <button className="ghost-button" onClick={() => setShowAdd(false)}>
                取消
              </button>
              <button className="primary-button">创建实例</button>
            </div>
          </div>
        </div>
      )}

      {showLogs && (
        <div className="modal-backdrop" onClick={() => setShowLogs(false)}>
          <div className="modal-card large" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <div>
                <h3>查看日志</h3>
                <p>实例 {selected.id} 的日志窗口原型。</p>
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

            <pre className="log-view">{logTab === 'stderr' ? logsMock.stderr : logsMock.stdout}</pre>

            <div className="modal-actions">
              <button className="ghost-button">打开日志目录</button>
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
