import React, { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type Node,
  type NodeProps,
} from 'reactflow'
import 'reactflow/dist/style.css'
import hljs from 'highlight.js/lib/core'
import cpp from 'highlight.js/lib/languages/cpp'
import x86asm from 'highlight.js/lib/languages/x86asm'
import 'highlight.js/styles/github-dark.css'

hljs.registerLanguage('cpp', cpp)
hljs.registerLanguage('x86asm', x86asm)

// Add clickable function links to highlighted HTML
function addFunctionLinks(
  html: string,
  entryAddrToId: Map<string, string>,
  _nameToId: Map<string, string>,
  _onNavigate: (fid: string) => void,
  displayNameById: Map<string, string>
): string {
  // Replace function name patterns with clickable spans
  let result = html
  
  // Pattern 1: FUN_00401000, thunk_FUN_00401000
  result = result.replace(/\b((?:FUN_|thunk_FUN_)([0-9A-Fa-f]+))\b/g, (match, _fullName, addr) => {
    const lowerAddr = addr.toLowerCase()
    const fid = entryAddrToId.get(lowerAddr) || entryAddrToId.get(`0x${lowerAddr}`)
    if (fid) {
      const displayName = displayNameById.get(fid) || match
      return `<span class="codeLink" data-fid="${fid}" title="${fid}">${displayName}</span>`
    }
    return match
  })
  
  // Pattern 2: sub_00401000, function_00401000
  result = result.replace(/\b((?:sub|function)_([0-9A-Fa-f]+))\b/g, (match, _fullName, addr) => {
    const lowerAddr = addr.toLowerCase()
    const fid = entryAddrToId.get(lowerAddr) || entryAddrToId.get(`0x${lowerAddr}`)
    if (fid) {
      const displayName = displayNameById.get(fid) || match
      return `<span class="codeLink" data-fid="${fid}" title="${fid}">${displayName}</span>`
    }
    return match
  })
  
  return result
}

type Analysis = {
  sample?: { entry_point?: string; image_base?: string; path?: string }
  ui?: { default_function_id?: string }
  strings?: Array<{ addr: string; value: string; len?: number; type?: string | null }>
  functions?: Array<{
    id: string
    name: string
    entry: string
    size: number
    calls_out?: string[]
    called_by?: string[]
  }>
}

type AiResult = {
  function_id: string
  status: string
  pseudocode?: string
  proposed_name?: string | null
  signature?: string | null
  summary_ja?: string
  confidence?: number
  error?: string
  model?: string
  analysis_hash?: string
  updated_at?: string
}

type IndexEntry = {
  status?: 'not_started' | 'queued' | 'running' | 'ok' | 'error'
  updated_at?: string
  proposed_name?: string
  confidence?: number
  model?: string | null
  queued_at?: string | null
  started_at?: string | null
  finished_at?: string | null
  total_ms?: number | null
  api_ms?: number | null
  error?: string
}

type SortKey = 'entry' | 'name' | 'size' | 'status' | 'updated'

type RecentJob = {
  job_id: string
  created_at?: string | null
  source_type?: string | null
  source_path?: string | null
  original_name?: string | null
  sample_path?: string | null
  analyzed?: boolean
  extract_stage?: string | null
}

const apiBase = ''

function useSSE(jobId: string | null, onIndex: (index: Record<string, IndexEntry>) => void) {
  useEffect(() => {
    if (!jobId) return
    const es = new EventSource(`${apiBase}/api/jobs/${jobId}/stream`)
    es.addEventListener('function_status', (ev: MessageEvent) => {
      try {
        onIndex(JSON.parse(ev.data))
      } catch {
        // ignore
      }
    })
    es.onerror = () => {
      // keep it; browser will retry
    }
    return () => es.close()
  }, [jobId, onIndex])
}

function useLocalStorageState<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key)
      if (!raw) return initial
      return JSON.parse(raw) as T
    } catch {
      return initial
    }
  })

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // ignore
    }
  }, [key, value])

  return [value, setValue] as const
}

function useWindowWidth() {
  const [w, setW] = useState<number>(() => (typeof window !== 'undefined' ? window.innerWidth : 1200))
  useEffect(() => {
    const onResize = () => setW(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return w
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

function escapeRegex(str: string) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function parseDisasm(text: string) {
  const lines = text.split(/\r?\n/)
  const rows: Array<{ ln: number; addr: string; inst: string }> = []
  let ln = 1
  for (const line of lines) {
    const t = line.trimEnd()
    if (!t.trim()) {
      ln++
      continue
    }
    const m = t.match(/^([0-9A-Fa-f]{8,16})\s+(.*)$/)
    if (m) rows.push({ ln, addr: m[1], inst: m[2] })
    else rows.push({ ln, addr: '', inst: t })
    ln++
  }
  return rows
}

function statusBadgeClass(st?: string) {
  if (st === 'ok') return 'badge badgeOk'
  if (st === 'error') return 'badge badgeErr'
  if (st === 'running' || st === 'queued') return 'badge badgeRun'
  return 'badge'
}

function fmtJst(v: any) {
  if (v == null) return ''
  // unix seconds
  if (typeof v === 'number' && isFinite(v)) {
    const d = new Date(v * 1000)
    return d.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false })
  }
  if (typeof v !== 'string') return String(v)
  const s = v.trim()
  if (!s) return ''
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  return d.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false })
}

function JsonPre({ value }: { value: any }) {
  return (
    <pre
      style={{
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        padding: 10,
        borderRadius: 10,
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.08)',
        margin: 0,
      }}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

function tryParseAiJson(text?: string) {
  const raw = (text ?? '').trim()
  if (!raw) return null

  let s = raw
  if (s.startsWith('```')) {
    const lines = s.split(/\r?\n/)
    s = lines.slice(1).join('\n')
    s = s.replace(/\n```\s*$/m, '').trim()
  }

  if (s.startsWith('{')) {
    try {
      return JSON.parse(s)
    } catch {
      // fallthrough
    }
  }

  // Extract first {...} block (best-effort)
  const m = s.match(/\{[\s\S]*\}/)
  if (m) {
    try {
      return JSON.parse(m[0])
    } catch {
      return null
    }
  }

  return null
}

function extractFirstCodeBlock(text?: string) {
  const s0 = (text ?? '').trim()
  if (!s0) return null

  const re = /```(?:c|cpp|C)?\s*\n([\s\S]*?)\n```/

  // normal (real newlines)
  let m = s0.match(re)
  if (m) return m[1].trim()

  // some model outputs contain literal "\\n" inside strings
  const s = s0.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"')
  m = s.match(re)
  if (m) return m[1].trim()

  // Salvage: JSON-ish wrapper where "pseudocode" is a string containing code, but fences are unclosed.
  const pm = s0.match(/"pseudocode"\s*:\s*"([\s\S]*)/)
  if (pm) {
    let body = pm[1]
    // stop at next top-level key if present
    const stop = body.search(/\n\s*"[a-zA-Z_]+"\s*:/)
    if (stop > 0) body = body.slice(0, stop)
    body = body.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"')
    // strip a leading code fence if present
    body = body.replace(/^```[a-zA-Z]*\s*\n?/, '')
    return body.trim()
  }

  return null
}

function normalizeAiResult(data: AiResult): AiResult {
  if (!data) return data
  if (data.status !== 'ok') return data
  if (!data.pseudocode) return data

  const obj = tryParseAiJson(data.pseudocode)
  if (obj && typeof obj === 'object') {
    const pc = (obj as any).pseudocode
    const pn = (obj as any).proposed_name
    const sig = (obj as any).signature
    const sumJa = (obj as any).summary_ja
    const conf = (obj as any).confidence

    // If pc itself is a fenced block, unwrap it
    const unwrappedPc = typeof pc === 'string' ? extractFirstCodeBlock(pc) ?? pc : null

    return {
      ...data,
      pseudocode: unwrappedPc ?? (typeof pc === 'string' ? pc : data.pseudocode),
      proposed_name: (pn ?? data.proposed_name) as any,
      signature: (sig ?? data.signature) as any,
      summary_ja: (typeof sumJa === 'string' ? sumJa : data.summary_ja) as any,
      confidence: typeof conf === 'number' ? conf : data.confidence,
    }
  }

  // Fallback: if the pseudocode is actually a json/code wrapper, show the first code block.
  const cb = extractFirstCodeBlock(data.pseudocode)
  if (cb) return { ...data, pseudocode: cb }

  return data
}

// CallTreeView Component
function CFGNode({ data }: NodeProps<{ title: string; summary: string; hasSummary: boolean }>) {
  return (
    <div
      style={{
        width: 300,
        height: 140,
        padding: 12,
        borderRadius: 10,
        border: '1px solid rgba(255,255,255,0.16)',
        background: 'rgba(10,10,10,0.85)',
        color: 'rgba(255,255,255,0.92)',
        fontSize: 13,
        lineHeight: 1.45,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      {/* connection handles */}
      <Handle type='target' position={Position.Top} style={{ background: 'rgba(255,255,255,0.55)', border: '1px solid rgba(0,0,0,0.35)' }} />
      <Handle type='source' position={Position.Bottom} style={{ background: 'rgba(255,255,255,0.55)', border: '1px solid rgba(0,0,0,0.35)' }} />

      <div style={{ fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{data.title}</div>
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          whiteSpace: 'pre-wrap',
          color: data.hasSummary ? 'rgba(255,255,255,0.88)' : 'rgba(255,255,255,0.45)',
          borderTop: '1px solid rgba(255,255,255,0.08)',
          paddingTop: 8,
        }}
      >
        {data.summary}
      </div>
    </div>
  )
}

function CallTreeView({
  functions,
  selected,
  onNavigate,
  displayName,
}: {
  functions: Array<{
    id: string
    name: string
    entry: string
    size: number
    calls_out?: string[]
    called_by?: string[]
  }>
  selected: string | null
  onNavigate: (fid: string) => void
  displayName: (fid: string) => string
}) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<'tree' | 'list'>('tree')

  // Build function map
  const funcMap = useMemo(() => {
    const map = new Map<string, typeof functions[0]>()
    functions.forEach((f) => map.set(f.id, f))
    return map
  }, [functions])

  // Find entry point or main-like functions
  const entryPoints = useMemo(() => {
    const entries = functions.filter((f) => 
      f.name.toLowerCase().includes('entry') ||
      f.name.toLowerCase().includes('main') ||
      f.name === 'start' ||
      (f.called_by && f.called_by.length === 0)
    )
    return entries.length > 0 ? entries : [functions[0]]
  }, [functions])

  const toggleNode = (id: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const renderTreeNode = (
    fid: string,
    depth: number,
    visited: Set<string>,
    via?: { from: string; idx: number } | null,
  ): React.ReactElement | null => {
    if (visited.has(fid)) {
      return (
        <div
          key={`${fid}-${depth}`}
          style={{ paddingLeft: depth * 20, cursor: 'pointer', opacity: 0.6 }}
          className='fnItem'
        >
          <div className='fnMeta'>
            <div className='fnName'>↻ {displayName(fid) || fid} (circular)</div>
          </div>
        </div>
      )
    }

    const func = funcMap.get(fid)
    if (!func) {
      // External / unknown callee (not part of extracted function list)
      return (
        <div
          key={`${fid}-${depth}`}
          className='fnItem'
          style={{
            paddingLeft: depth * 20,
            cursor: 'default',
            opacity: 0.7,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
          title='external/unknown'
        >
          <span style={{ width: 16, display: 'inline-block' }}></span>
          <div className='fnMeta' style={{ flex: 1 }}>
            <div className='fnName'>
              {via ? <span className='callEdgePrefix'>↳ {via.idx}</span> : null}
              {fid}
              <span className='secondary' style={{ marginLeft: 8 }}>
                (external)
              </span>
            </div>
          </div>
        </div>
      )
    }

    const callsOut = func.calls_out || []
    const hasChildren = callsOut.length > 0
    const isExpanded = expandedNodes.has(fid)
    const isSelected = fid === selected

    const nextVisited = new Set(visited)
    nextVisited.add(fid)

    return (
      <div key={`${fid}-${depth}`} style={{ marginBottom: 2 }}>
        <div
          className={`fnItem ${isSelected ? 'fnItemSelected' : ''}`}
          style={{
            paddingLeft: depth * 20,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
          onClick={(e) => {
            e.stopPropagation()
            onNavigate(fid)
          }}
        >
          {hasChildren && (
            <span
              onClick={(e) => {
                e.stopPropagation()
                toggleNode(fid)
              }}
              style={{ 
                cursor: 'pointer', 
                userSelect: 'none',
                width: 16,
                display: 'inline-block',
              }}
            >
              {isExpanded ? '▼' : '▶'}
            </span>
          )}
          {!hasChildren && <span style={{ width: 16, display: 'inline-block' }}></span>}
          <div className='fnMeta' style={{ flex: 1 }}>
            <div className='fnName'>
              {via ? <span className='callEdgePrefix'>↳ {via.idx}</span> : null}
              {displayName(func.id)}
            </div>
            <div className='fnSub'>
              <span>@ {func.entry}</span>
              <span>{func.size} bytes</span>
              {callsOut.length > 0 && <span>→ {callsOut.length} calls</span>}
            </div>
          </div>
        </div>
        {hasChildren && isExpanded && (
          <div>
            {callsOut.map((childId, i) => renderTreeNode(childId, depth + 1, nextVisited, { from: fid, idx: i + 1 }))}
          </div>
        )}
      </div>
    )
  }

  const renderList = () => {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {functions.map((func) => {
          const callsOut = func.calls_out || []
          const isSelected = func.id === selected
          return (
            <div
              key={func.id}
              className={`fnItem ${isSelected ? 'fnItemSelected' : ''}`}
              onClick={() => onNavigate(func.id)}
              style={{ cursor: 'pointer' }}
            >
              <div className='fnMeta'>
                <div className='fnName'>{displayName(func.id)}</div>
                <div className='fnSub'>
                  <span>@ {func.entry}</span>
                  <span>{func.size} bytes</span>
                  {callsOut.length > 0 && <span>→ {callsOut.length} calls</span>}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div style={{ padding: 10 }}>
      <div style={{ marginBottom: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          className={viewMode === 'tree' ? 'smallBtn' : 'smallBtn'}
          onClick={() => setViewMode('tree')}
          style={{ 
            background: viewMode === 'tree' ? 'rgba(99, 102, 241, 0.3)' : undefined,
          }}
        >
          Tree View
        </button>
        <button
          className='smallBtn'
          onClick={() => setViewMode('list')}
          style={{ 
            background: viewMode === 'list' ? 'rgba(99, 102, 241, 0.3)' : undefined,
          }}
        >
          List View
        </button>
        <button
          className='smallBtn'
          onClick={() => {
            // Expanding the whole call graph can explode the DOM and crash the tab.
            // Expand only a bounded neighborhood from entry points.
            const MAX_NODES = 300
            const MAX_DEPTH = 5

            const expanded = new Set<string>()
            const q: Array<{ id: string; depth: number }> = entryPoints.map((ep) => ({ id: ep.id, depth: 0 }))
            const seen = new Set<string>()

            while (q.length && expanded.size < MAX_NODES) {
              const cur = q.shift()!
              if (seen.has(cur.id)) continue
              seen.add(cur.id)

              const f = funcMap.get(cur.id)
              if (!f) continue

              const outs = f.calls_out || []
              if (outs.length) expanded.add(cur.id)

              if (cur.depth >= MAX_DEPTH) continue
              for (const child of outs) {
                // we still queue externals for display depth, but only expand known functions
                if (funcMap.has(child)) q.push({ id: child, depth: cur.depth + 1 })
              }
            }

            setExpandedNodes(expanded)
            if (expanded.size >= MAX_NODES) {
              alert(`Expand Allは重いので、入口から深さ${MAX_DEPTH} / 最大${MAX_NODES}ノードまでに制限して展開しました。`) 
            }
          }}
          title='Expand a limited portion of the tree to avoid browser OOM'
        >
          Expand (safe)
        </button>
        <button
          className='smallBtn'
          onClick={() => setExpandedNodes(new Set())}
        >
          Collapse All
        </button>
      </div>

      {viewMode === 'tree' ? (
        <div>
          <div className='secondary' style={{ marginBottom: 8, fontSize: 12 }}>
            Entry Points ({entryPoints.length})
          </div>
          {entryPoints.map((ep) => renderTreeNode(ep.id, 0, new Set(), null))}
        </div>
      ) : (
        renderList()
      )}
    </div>
  )
}

export default function App() {
  const width = useWindowWidth()
  const isMobile = width <= 900

  const [jobId, setJobId] = useState<string>(() => {
    try {
      return new URLSearchParams(window.location.search).get('job') ?? ''
    } catch {
      return ''
    }
  })

  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [index, setIndex] = useState<Record<string, IndexEntry>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [disasm, setDisasm] = useState<string>('')
  const [ghidraDecomp, setGhidraDecomp] = useState<string>('')
  const [ai, setAi] = useState<AiResult | null>(null)
  const [funcSummary, setFuncSummary] = useState<any>(null)
  const [showExeSummary, setShowExeSummary] = useState<boolean>(false)
  const [exeSummary, setExeSummary] = useState<any>(null)
  const [exeSummaryLogs, setExeSummaryLogs] = useState<any[]>([])

  const [showCFG, setShowCFG] = useState<boolean>(false)
  const [cfgRootId, setCfgRootId] = useState<string | null>(null)
  const [cfgData, setCfgData] = useState<any>(null)
  const [cfgLoading, setCfgLoading] = useState<boolean>(false)
  const [cfgError, setCfgError] = useState<string | null>(null)
  const [cfgDepth, setCfgDepth] = useState<number>(3)
  const [cfgNodes, setCfgNodes] = useState<Node[]>([])
  const [cfgEdges, setCfgEdges] = useState<Edge[]>([])
  const [capaData, setCapaData] = useState<any>(null)
  const [mainGuess, setMainGuess] = useState<{ function_id: string; reason?: string } | null>(null)
  const [mainGuessError, setMainGuessError] = useState<string | null>(null)
  const [showMainCandidates, setShowMainCandidates] = useState<boolean>(false)

  const [navHistory, setNavHistory] = useState<string[]>([])
  const [navPos, setNavPos] = useState<number>(-1)

  const [_callEdges, _setCallEdges] = useState<Record<string, string[]>>({})

  const [hoverDisasmLn, setHoverDisasmLn] = useState<number | null>(null)
  const [hoverPseudoLn, setHoverPseudoLn] = useState<number | null>(null)
  const [hoveredAddress, setHoveredAddress] = useState<string | null>(null)
  const disasmRowRefs = useRef<Map<string, HTMLDivElement>>(new Map())

  const [providerChoice, setProviderChoice] = useLocalStorageState<string>('autore.providerChoice', 'anthropic')
  const [modelChoice, setModelChoice] = useLocalStorageState<string>('autore.modelChoice', '')
  const [openaiBaseUrl, setOpenaiBaseUrl] = useLocalStorageState<string>('autore.openaiBaseUrl', '')
  const [openaiApiKey, setOpenaiApiKey] = useLocalStorageState<string>('autore.openaiApiKey', '')
  const [openaiApiMode, setOpenaiApiMode] = useLocalStorageState<string>('autore.openaiApiMode', 'chat')
  const [openaiReasoning, setOpenaiReasoning] = useLocalStorageState<string>('autore.openaiReasoning', '')

  // Settings
  const [showSettings, setShowSettings] = useState(false)

  // Find main automation
  const [autoAiOnFindMain, setAutoAiOnFindMain] = useLocalStorageState<boolean>('autore.autoAiOnFindMain', true)
  const [autoAiTopN, setAutoAiTopN] = useLocalStorageState<number>('autore.autoAiTopN', 3)

  // Guardrail (worker-side retries) overrides
  const [guardrailMaxAttempts, setGuardrailMaxAttempts] = useLocalStorageState<number>('autore.guardrailMaxAttempts', 4)
  const [guardrailMinConfidence, setGuardrailMinConfidence] = useLocalStorageState<number>('autore.guardrailMinConfidence', 0.55)

  // Provider defaults (used when Model is empty)
  const [anthropicDefaultModel, setAnthropicDefaultModel] = useLocalStorageState<string>('autore.anthropicDefaultModel', 'claude-sonnet-4-5')
  const [openaiDefaultModel, setOpenaiDefaultModel] = useLocalStorageState<string>('autore.openaiDefaultModel', 'gpt-oss-120b')
  const [showDebug, setShowDebug] = useLocalStorageState<boolean>('autore.showDebug', false)
  // If true, selecting a function auto-enqueues AI decompile (default: OFF)
  const [autoRunOnSelect, setAutoRunOnSelect] = useLocalStorageState<boolean>('autore.autoRunOnSelect', false)
  // If true, use multi-stage reasoning (summary -> pseudocode -> consistency check)
  const [multiStageEnabled, setMultiStageEnabled] = useLocalStorageState<boolean>('autore.multiStage', true)
  const [debugData, setDebugData] = useState<any>(null)
  const [debugQueue, setDebugQueue] = useState<any>(null)
  const [debugExtract, setDebugExtract] = useState<any>(null)
  const [debugSettings, setDebugSettings] = useState<any>(null)
  const [lastDecompileResp, setLastDecompileResp] = useState<any>(null)
  const [lastDecompileFid, setLastDecompileFid] = useState<string | null>(null)
  
  const [calledRanking, setCalledRanking] = useState<any[]>([])
  const [showRanking, setShowRanking] = useState<boolean>(false)
  const [showCallTree, setShowCallTree] = useLocalStorageState<boolean>('autore.showCallTree', false)
  const [showCapaModal, setShowCapaModal] = useState<boolean>(false)
  const [showXrefs, setShowXrefs] = useState<boolean>(false)
  const [showStrings, setShowStrings] = useState<boolean>(false)
  
  // Chat assistant
  const [showChat, setShowChat] = useState<boolean>(false)
  const [chatMinimized, setChatMinimized] = useState<boolean>(false)
  const [chatPosition, setChatPosition] = useState<{ x: number; y: number }>({ x: 20, y: 20 })
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; timestamp: string; debug?: any }>>([])
  const [chatInput, setChatInput] = useState<string>('')
  const [chatLoading, setChatLoading] = useState<boolean>(false)
  const [chatProvider, setChatProvider] = useLocalStorageState<'openai' | 'anthropic'>('autore.chat.provider', 'openai')
  const [chatModel, setChatModel] = useLocalStorageState<string>('autore.chat.model', '')
  const [chatError, setChatError] = useState<string | null>(null)
  const [showChatDebug, setShowChatDebug] = useLocalStorageState<boolean>('autore.chat.showDebug', false)
  const chatMessagesEndRef = useRef<HTMLDivElement>(null)
  
  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    chatMessagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages])
  
  const [stringQuery, setStringQuery] = useState<string>('')
  const [stringMinLen, setStringMinLen] = useState<number>(0)
  const [stringMaxLen, setStringMaxLen] = useState<number>(0)

  const [liveLogs, setLiveLogs] = useState<any[]>([])
  const [liveLogsConnected, setLiveLogsConnected] = useState<boolean>(false)
  const [liveLogsFilterSelected, setLiveLogsFilterSelected] = useLocalStorageState<boolean>('autore.debug.filterSelected', true)

  const [entryOnly, setEntryOnly] = useLocalStorageState<boolean>('autore.entryOnly', (() => {
    try {
      return new URLSearchParams(window.location.search).get('entry') === '1'
    } catch {
      return false
    }
  })())

  const [winApiOnly, setWinApiOnly] = useLocalStorageState<boolean>('autore.winApiOnly', false)

  const [sidebarWidth, setSidebarWidth] = useLocalStorageState<number>('autore.sidebarWidth', 380)
  const [sidebarCollapsed, setSidebarCollapsed] = useLocalStorageState<boolean>('autore.sidebarCollapsed', false)
  // Desktop pane splits (0..1): splitA between Disasm|Ghidra, splitB between Ghidra|AI
  const [splitA, setSplitA] = useLocalStorageState<number>('autore.splitA', 0.33)
  const [splitB, setSplitB] = useLocalStorageState<number>('autore.splitB', 0.67)
  const [disasmCollapsed, setDisasmCollapsed] = useLocalStorageState<boolean>('autore.disasmCollapsed', false)
  const [disasmSplitPrev, setDisasmSplitPrev] = useLocalStorageState<number>('autore.disasmSplitPrev', 0.33)

  const [fnQuery, setFnQuery] = useLocalStorageState<string>('autore.fnQuery', '')
  const [sortKey, setSortKey] = useLocalStorageState<SortKey>('autore.sortKey', 'entry')

  const [recentQuery, setRecentQuery] = useLocalStorageState<string>('autore.recentQuery', '')
  const [recentJobs, setRecentJobs] = useState<RecentJob[]>([])
  const [recentLoading, setRecentLoading] = useState<boolean>(false)

  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false)
  const [mobileTab, setMobileTab] = useState<'disasm' | 'ghidra' | 'ai'>('disasm')

  useSSE(jobId || null, setIndex)

  const functions = useMemo(() => analysis?.functions ?? [], [analysis])

  const entryAddrToId = useMemo(() => {
    const m = new Map<string, string>()
    for (const f of functions) {
      const e = (f as any).entry
      if (!e) continue
      const key = String(e).trim().toLowerCase()
      if (key) m.set(key, f.id)
      // also allow 0x-prefixed
      if (!key.startsWith('0x')) m.set(`0x${key}`, f.id)
    }
    return m
  }, [functions])

  const nameToId = useMemo(() => {
    const m = new Map<string, string>()
    for (const f of functions) {
      if (f.name) m.set(String(f.name).toLowerCase(), f.id)
      // also map id itself (helps with names like "entry")
      if (f.id) m.set(String(f.id).toLowerCase(), f.id)
    }
    return m
  }, [functions])

  const entryFunctionId = useMemo(() => {
    const df = analysis?.ui?.default_function_id
    if (df) return df
    const fs = analysis?.functions ?? []
    const hit = fs.find((f: any) => {
      const v = String(f.entry ?? '').toLowerCase()
      return v === 'true' || v === '1' || v === 'yes' || v === 'entry'
    })
    return hit?.id
  }, [analysis])

  const selectedFn = useMemo(() => functions.find((f) => f.id === selected) ?? null, [functions, selected])
  const funcById = useMemo(() => new Map(functions.map((f) => [f.id, f])), [functions])

  // Unified display name: always prefer AI-proposed name when available.
  const displayNameById = useMemo(() => {
    const m = new Map<string, string>()
    for (const f of functions as any[]) {
      const proposed = index[f.id]?.proposed_name
      const base = proposed || f.name || f.id
      m.set(f.id, String(base))
    }
    return m
  }, [functions, index])

  const displayName = (id?: string | null) => {
    if (!id) return ''
    return displayNameById.get(id) ?? id
  }

  const filteredFunctions = useMemo(() => {
    let arr = functions

    if (entryOnly && entryFunctionId) {
      arr = arr.filter((f) => f.id === entryFunctionId)
    }

    if (winApiOnly) {
      arr = arr.filter((f: any) => Boolean((f as any).is_winapi))
    }

    const q = fnQuery.trim().toLowerCase()
    if (q) {
      arr = arr.filter((f) => {
        const st = index[f.id]
        const hay = `${f.id} ${f.name} ${displayNameById.get(f.id) ?? ''} ${f.entry} ${st?.proposed_name ?? ''}`.toLowerCase()
        return hay.includes(q)
      })
    }

    const scoreStatus = (s?: string) => {
      if (s === 'error') return 4
      if (s === 'running') return 3
      if (s === 'queued') return 2
      if (s === 'ok') return 1
      return 0
    }

    const sorters: Record<SortKey, (a: any, b: any) => number> = {
      entry: (a, b) => {
        const ae = entryFunctionId && a.id === entryFunctionId ? 1 : 0
        const be = entryFunctionId && b.id === entryFunctionId ? 1 : 0
        if (ae !== be) return be - ae
        return (b.size ?? 0) - (a.size ?? 0)
      },
      name: (a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)),
      size: (a, b) => (b.size ?? 0) - (a.size ?? 0),
      status: (a, b) => scoreStatus(index[b.id]?.status) - scoreStatus(index[a.id]?.status),
      updated: (a, b) => String(index[b.id]?.updated_at ?? '').localeCompare(String(index[a.id]?.updated_at ?? '')),
    }

    const sorted = [...arr].sort(sorters[sortKey])

    // de-dupe by id (same name functions with different entry points)
    const seen = new Set<string>()
    const deduped: typeof sorted = []
    for (const f of sorted) {
      const id = String(f.id).toLowerCase()
      if (seen.has(id)) continue
      seen.add(id)
      deduped.push(f)
    }

    return deduped
  }, [functions, entryOnly, winApiOnly, entryFunctionId, fnQuery, index, sortKey])

  const mainCandidates = useMemo(() => {
    // Heuristic candidates list with "reasons" shown in UI.
    const mk = (id: string) => funcById.get(id)

    const hasAny = (calls: string[], keys: string[]) => {
      const low = calls.map((x) => String(x).toLowerCase())
      return keys.filter((k) => low.some((c) => c.includes(k)))
    }

    const guiKeys = [
      'getmessage',
      'dispatchmessage',
      'translatemessage',
      'createwindow',
      'showwindow',
      'registerclassex',
      'defwindowproc',
    ]
    const argvKeys = ['getcommandline', '__p__acmdln', '__wgetmainargs', '__getmainargs', 'argv']
    const crtKeys = ['__security_init_cookie', 'exitprocess', '_cexit', 'exit']

    const scored: Array<{ id: string; score: number; reasons: string[]; label: string; kind?: string }> = []

    for (const f of functions) {
      const calls = f.calls_out ?? []
      const n = String(f.name || f.id)
      const lowName = n.toLowerCase()

      const reasons: string[] = []
      let score = 0

      // name bias
      if (/^w?winmain$/.test(lowName)) {
        score += 0.9
        reasons.push('name: WinMain/wWinMain')
      } else if (/^w?main$/.test(lowName) || lowName === 'main') {
        score += 0.82
        reasons.push('name: main/wmain')
      } else if (lowName.includes('winmain')) {
        score += 0.6
        reasons.push('name contains winmain')
      } else if (/(^|\b)main(\b|$)/.test(lowName)) {
        score += 0.45
        reasons.push('name contains main')
      }

      // GUI loop
      const guiHit = hasAny(calls, guiKeys)
      if (guiHit.length) {
        score += Math.min(0.55, 0.15 + guiHit.length * 0.08)
        reasons.push(`GUI APIs: ${guiHit.slice(0, 4).join(', ')}`)
      }

      // argv setup
      const argvHit = hasAny(calls, argvKeys)
      if (argvHit.length) {
        score += Math.min(0.35, 0.12 + argvHit.length * 0.07)
        reasons.push(`argv/setup: ${argvHit.slice(0, 4).join(', ')}`)
      }

      // CRT-ish
      const crtHit = hasAny(calls, crtKeys)
      if (crtHit.length) {
        score += Math.min(0.95, 0.6 + crtHit.length * 0.1)
        reasons.push(`CRT-ish: ${crtHit.slice(0, 4).join(', ')}`)
      }

      // called-by weight (popular funcs more likely central)
      const cb = (f.called_by ?? []).length
      score += Math.min(0.25, cb / 200)
      if (cb >= 10) reasons.push(`called_by: ${cb}`)

      // hard-label entry/tls
      if (lowName === 'entry') {
        reasons.push('OEP: entry')
      }
      if (lowName.startsWith('tls_callback')) {
        reasons.push('TLS callback')
      }

      // keep if any signal
      if (score >= 0.35 || lowName === 'entry' || lowName.startsWith('tls_callback')) {
        scored.push({ id: f.id, score, reasons, label: displayNameById.get(f.id) ?? f.name ?? f.id })
      }
    }

    // ensure "entry" shows even if no calls_out
    const entry = functions.find((f) => String(f.name || f.id).toLowerCase() === 'entry')
    if (entry && !scored.some((x) => x.id === entry.id)) {
      scored.push({ id: entry.id, score: 0.95, reasons: ['OEP: entry', 'CRT/stub likely'], label: displayNameById.get(entry.id) ?? entry.name ?? entry.id })
    }

    // also include backend-predicted main on top
    if (mainGuess?.function_id && !scored.some((x) => x.id === mainGuess.function_id)) {
      const f = mk(mainGuess.function_id)
      scored.push({
        id: mainGuess.function_id,
        label: displayNameById.get(mainGuess.function_id) ?? f?.name ?? mainGuess.function_id,
        score: 0.99,
        reasons: [mainGuess.reason ? `predicted: ${mainGuess.reason}` : 'predicted'],
      })
    }

    scored.sort((a, b) => b.score - a.score)
    return scored.slice(0, 12)
  }, [functions, funcById, mainGuess, displayNameById])

  // User Entry shown in sidebar: top 3 candidates with score + reasons.
  // Prefer mainCandidates (calls-based heuristics) so it works even when names are generic.
  const userEntryCandidates = useMemo(() => {
    const isEntrypointish = (id: string) => {
      const f = funcById.get(id)
      const n = String(f?.name || id).toLowerCase()
      return n === 'entry' || n.startsWith('tls_callback')
    }

    const primary = mainCandidates.filter((c) => !isEntrypointish(c.id)).slice(0, 3)
    if (primary.length >= 3) return primary

    // fall back: allow entry/tls if we don't have enough
    const secondary = mainCandidates.filter((c) => !primary.some((p) => p.id === c.id)).slice(0, 3 - primary.length)
    return [...primary, ...secondary]
  }, [mainCandidates, funcById])


  async function loadAnalysis(id: string) {
    setAnalysis(null)
    setSelected(null)
    setNavHistory([])
    setNavPos(-1)
    _setCallEdges({})
    setMainGuess(null)
    setMainGuessError(null)

    const r = await fetch(`${apiBase}/api/jobs/${id}/analysis`)
    if (r.status === 202) {
      alert('解析中です。少し待ってから再読み込みしてください。')
      return
    }
    const data = (await r.json()) as Analysis
    setAnalysis(data)

    const df = data.ui?.default_function_id
    const fs = data.functions ?? []
    const entry =
      df ??
      fs.find((f: any) => {
        const v = String(f.entry ?? '').toLowerCase()
        return v === 'true' || v === '1' || v === 'yes' || v === 'entry'
      })?.id

    if (entry) navigateTo(entry)
    
    // Load CAPA results (non-blocking)
    loadCapa(id).catch(() => {})
  }

  async function loadDisasm(id: string, fid: string) {
    const r = await fetch(`${apiBase}/api/jobs/${id}/functions/${fid}/disasm`)
    setDisasm(await r.text())
  }

  async function loadAi(id: string, fid: string) {
    const r = await fetch(`${apiBase}/api/jobs/${id}/functions/${fid}`)
    const data = normalizeAiResult((await r.json()) as AiResult)
    setAi(data)
    return data
  }

  async function loadFuncSummary(id: string, fid: string) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/functions/${fid}/summary`)
      const j = await r.json().catch(() => null)
      setFuncSummary(j)
      return j
    } catch {
      setFuncSummary(null)
      return null
    }
  }

  async function loadExeSummary(id: string) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/exe_summary`)
      const j = await r.json().catch(() => null)
      setExeSummary(j)
      return j
    } catch {
      setExeSummary(null)
      return null
    }
  }

  async function loadExeSummaryLogs(id: string) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/debug/logs?n=300`)
      const j = await r.json().catch(() => null)
      const lines = Array.isArray(j?.lines) ? j.lines : []
      const filtered = lines.filter((x: any) => x?.task === 'summarize_exe' || x?.function_id === '__exe__' || String(x?.event || '').includes('exe_summary'))
      setExeSummaryLogs(filtered)
      return filtered
    } catch {
      setExeSummaryLogs([])
      return []
    }
  }

  async function loadCFG(id: string, fid: string, depth: number) {
    try {
      setCfgLoading(true)
      setCfgError(null)
      const d = Math.max(1, Math.min(3, Number(depth || 3)))
      const r = await fetch(`${apiBase}/api/jobs/${id}/callgraph?root=${encodeURIComponent(fid)}&depth=${d}`)
      const j = await r.json().catch(() => null)
      setCfgData(j)
      return j
    } catch (e: any) {
      setCfgError(String(e?.message || e))
      setCfgData(null)
      return null
    } finally {
      setCfgLoading(false)
    }
  }

  // Build draggable CFG nodes/edges from cfgData (kept in state so dragging works).
  useEffect(() => {
    if (!showCFG) return
    if (!cfgData || (cfgData as any)?.status === 'analyzing') return

    const nodesRaw = Array.isArray((cfgData as any)?.nodes) ? (cfgData as any).nodes : []
    const edgesRaw = Array.isArray((cfgData as any)?.edges) ? (cfgData as any).edges : []

    const rootId = String((cfgData as any)?.root || cfgRootId || selected || '')

    // adjacency
    const children = new Map<string, string[]>()
    for (const e of edgesRaw) {
      const a = String(e.from)
      const b = String(e.to)
      const arr = children.get(a) || []
      arr.push(b)
      children.set(a, arr)
    }

    // depth from root
    const depthById = new Map<string, number>()
    if (rootId) depthById.set(rootId, 0)
    const q: string[] = rootId ? [rootId] : []
    while (q.length) {
      const cur = q.shift()!
      const d = depthById.get(cur) ?? 0
      if (d >= cfgDepth) continue
      for (const nxt of children.get(cur) || []) {
        if (!depthById.has(nxt)) {
          depthById.set(nxt, d + 1)
          q.push(nxt)
        }
      }
    }

    const byDepth = new Map<number, string[]>()
    for (const n of nodesRaw) {
      const id = String(n.id)
      const d = depthById.get(id) ?? 999
      const arr = byDepth.get(d) || []
      arr.push(id)
      byDepth.set(d, arr)
    }
    for (const arr of byDepth.values()) arr.sort()

    const positions = new Map<string, { x: number; y: number }>()
    const XGAP = 360
    const YGAP = 320
    const depths = Array.from(byDepth.keys()).sort((a, b) => a - b)
    for (const d0 of depths) {
      const ids = byDepth.get(d0) || []
      const d = d0 === 999 ? cfgDepth + 1 : d0
      const center = (ids.length - 1) / 2
      for (let i = 0; i < ids.length; i++) {
        positions.set(ids[i], { x: (i - center) * XGAP, y: d * YGAP })
      }
    }

    const nextNodes: Node[] = nodesRaw.map((n: any) => {
      const id = String(n.id)
      const title = `${displayName(id)}`
      const sj = typeof n.summary_ja === 'string' ? n.summary_ja.trim() : ''
      const hasSummary = Boolean(sj)
      return {
        id,
        type: 'cfgNode',
        position: positions.get(id) || { x: 0, y: 0 },
        data: { title, summary: hasSummary ? sj : '(no summary)', hasSummary },
      }
    })

    const nextEdges: Edge[] = edgesRaw.map((e: any, i: number) => ({
      id: `e-${i}-${e.from}-${e.to}`,
      source: String(e.from),
      target: String(e.to),
      animated: false,
      style: { stroke: 'rgba(255,255,255,0.35)' },
    }))

    setCfgNodes(nextNodes)
    setCfgEdges(nextEdges)
  }, [showCFG, cfgData, cfgRootId, selected, cfgDepth, index])

  async function loadGhidraDecomp(id: string, fid: string) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/functions/${fid}/ghidra`)
      if (!r.ok) {
        setGhidraDecomp('')
        return
      }
      setGhidraDecomp(await r.text())
    } catch {
      setGhidraDecomp('')
    }
  }

  async function loadCapa(id: string) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/capa`)
      if (!r.ok) {
        setCapaData({ error: 'CAPA results not available' })
        return
      }
      const data = await r.json()
      setCapaData(data)
    } catch {
      setCapaData({ error: 'Failed to load CAPA results' })
    }
  }

  async function requestDecompile(id: string, fid: string, opts?: { force?: boolean }) {
    const fd = new FormData()
    if (opts?.force) fd.set('force', 'true')
    if (providerChoice) fd.set('provider', providerChoice)

    // Model selection: if empty, fall back to provider-specific default model
    const effectiveModel =
      modelChoice || (providerChoice === 'openai' ? openaiDefaultModel : anthropicDefaultModel) || ''
    if (effectiveModel) fd.set('model', effectiveModel)

    // Guardrail overrides (worker may also have env defaults)
    fd.set('guardrail_max_attempts', String(guardrailMaxAttempts))
    fd.set('guardrail_min_confidence', String(guardrailMinConfidence))

    if (providerChoice === 'openai') {
      if (openaiBaseUrl.trim()) fd.set('openai_base_url', openaiBaseUrl.trim())
      if (openaiApiKey.trim()) fd.set('openai_api_key', openaiApiKey.trim())
      if (openaiApiMode.trim()) fd.set('openai_api_mode', openaiApiMode.trim())
      if (openaiReasoning.trim()) fd.set('openai_reasoning', openaiReasoning.trim())
    }
    fd.set('multi_stage', multiStageEnabled ? 'true' : 'false')
    const r = await fetch(`${apiBase}/api/jobs/${id}/functions/${fid}/decompile`, {
      method: 'POST',
      body: fd,
    })
    setLastDecompileFid(fid)
    try {
      const j = await r.json()
      setLastDecompileResp(j)
    } catch {
      setLastDecompileResp({ status: r.status })
    }
  }

  async function requestReextract(id: string) {
    const r = await fetch(`${apiBase}/api/jobs/${id}/reextract`, { method: 'POST' })
    if (!r.ok) {
      const t = await r.text()
      alert(t)
      return
    }

    // Immediately refresh Recent so the UI shows extract_stage=running.
    refreshRecentJobs()
    // And refresh again shortly after in case the status file appears with a delay.
    window.setTimeout(() => refreshRecentJobs(), 800)

    alert('Ghidra再抽出を開始しました（数分かかります）。Recentが自動更新されます。')
  }

  async function findMain(id: string, opts?: { autoDecompileTopN?: number }) {
    try {
      const r = await fetch(`${apiBase}/api/jobs/${id}/main`)
      if (r.status === 202) {
        alert('解析中です。少し待ってから再試行してください。')
        return
      }
      if (!r.ok) {
        const t = await r.text()
        setMainGuessError(t)
        alert(t)
        return
      }
      const data = (await r.json()) as { function_id: string; reason?: string }
      if (data?.function_id) {
        setMainGuessError(null)
        setMainGuess({ function_id: data.function_id, reason: data.reason })
        if (entryOnly && entryFunctionId && data.function_id !== entryFunctionId) setEntryOnly(false)
        navigateTo(data.function_id, { from: entryFunctionId || undefined, recordEdge: true })

        // Auto-enqueue AI decompile for top candidates (requested UX)
        const desiredN = opts?.autoDecompileTopN ?? (autoAiOnFindMain ? autoAiTopN : 0)
        const topN = Math.max(0, Math.min(desiredN, 10))
        if (topN > 0) {
          const ids = userEntryCandidates.slice(0, topN).map((c) => c.id)
          for (const fid of ids) {
            const st = index[fid]?.status
            if (st === 'queued' || st === 'running' || st === 'ok') continue
            await requestDecompile(id, fid)
          }
        }
      }
    } catch {
      // ignore
    }
  }

  async function createJobByPath(path: string) {
    const fd = new FormData()
    fd.set('path', path)
    const r = await fetch(`${apiBase}/api/jobs/by-path`, { method: 'POST', body: fd })
    if (!r.ok) {
      const t = await r.text()
      alert(t)
      return
    }
    const j = await r.json()
    setJobId(j.job_id)
    await loadAnalysis(j.job_id)
    refreshRecentJobs()
  }

  async function createJobUpload(f: File) {
    const fd = new FormData()
    fd.set('file', f)
    const r = await fetch(`${apiBase}/api/jobs`, { method: 'POST', body: fd })
    if (!r.ok) {
      const t = await r.text()
      alert(t)
      return
    }
    const j = await r.json()
    setJobId(j.job_id)
    await loadAnalysis(j.job_id)
    refreshRecentJobs()
  }

  async function refreshRecentJobs() {
    setRecentLoading(true)
    try {
      const qs = new URLSearchParams()
      qs.set('limit', '80')
      if (recentQuery.trim()) qs.set('q', recentQuery.trim())
      const r = await fetch(`${apiBase}/api/jobs?${qs.toString()}`)
      const data = (await r.json()) as { jobs: RecentJob[] }
      setRecentJobs(data.jobs ?? [])
    } catch {
      setRecentJobs([])
    } finally {
      setRecentLoading(false)
    }
  }

  async function deleteJob(id: string) {
    const ok = window.confirm(`Delete job ${id.slice(0, 10)}… ?\nThis will remove the uploaded file and ALL extracted/AI results.`)
    if (!ok) return
    const r = await fetch(`${apiBase}/api/jobs/${id}`, { method: 'DELETE' })
    if (!r.ok) {
      const t = await r.text()
      alert(t)
      return
    }
    // clear current view if deleting the active job
    if (jobId === id) {
      setJobId('')
      setAnalysis(null)
      setSelected(null)
      setDisasm('')
      setGhidraDecomp('')
      setAi(null)
      setIndex({})
    }
    refreshRecentJobs()
  }

  // Auto-load when job id is provided via URL (?job=<sha256>)
  useEffect(() => {
    refreshRecentJobs()
    if (!jobId) return
    loadAnalysis(jobId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Debounced recent-jobs search
  useEffect(() => {
    const t = window.setTimeout(() => refreshRecentJobs(), 250)
    return () => window.clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recentQuery])

  // Auto-refresh recent jobs if any are extracting
  useEffect(() => {
    const hasExtracting = recentJobs.some((j) => j.extract_stage && j.extract_stage !== 'done')
    if (!hasExtracting) return

    const interval = setInterval(() => {
      refreshRecentJobs()
      
      // If current job finished extracting, reload analysis
      const currentJob = recentJobs.find((j) => j.job_id === jobId)
      if (currentJob?.extract_stage === 'done' && jobId) {
        loadAnalysis(jobId)
      }
    }, 3000) // Refresh every 3 seconds

    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recentJobs, jobId])

  // When selection changes: load disasm + ghidra decompile + AI result
  // NOTE: AI decompile is manual by default (Run button). If autoRunOnSelect is enabled, enqueue only when not_started.
  useEffect(() => {
    if (!jobId || !selected) return
    ;(async () => {
      await loadDisasm(jobId, selected)
      await loadGhidraDecomp(jobId, selected)
      await loadFuncSummary(jobId, selected)
      const st = await loadAi(jobId, selected)
      if (autoRunOnSelect && st.status === 'not_started') {
        await requestDecompile(jobId, selected)
        setAi({ function_id: selected, status: 'queued' })
      }
    })()
  }, [jobId, selected, autoRunOnSelect])

  // Update AI panel when SSE changes
  useEffect(() => {
    if (!selected) return
    const st = index[selected]
    if (!st) return

    // Always refresh function summary when index changes (covers summarize task updates too).
    loadFuncSummary(jobId, selected)

    if (st.status === 'ok' || st.status === 'error') {
      loadAi(jobId, selected)
    } else {
      setAi((prev) => (prev ? { ...prev, status: st.status ?? prev.status } : prev))
    }
  }, [index, selected, jobId])

  // Auto-scroll disassembly when address is hovered from other views
  // DISABLED: Auto-scroll can be disruptive during manual navigation
  // useEffect(() => {
  //   if (!hoveredAddress) return
  //   const el = disasmRowRefs.current.get(hoveredAddress.toLowerCase().replace(/^0x/, ''))
  //   if (el) {
  //     el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  //   }
  // }, [hoveredAddress])

  // Pane dragging
  const dragRef = useRef<{ kind: 'sidebar' | 'split1' | 'split2'; startX: number; start: number; w: number } | null>(null)

  function beginSidebarResize(e: React.PointerEvent) {
    if (isMobile) return
    dragRef.current = { kind: 'sidebar', startX: e.clientX, start: sidebarWidth, w: 0 }
    ;(e.currentTarget as any).setPointerCapture?.(e.pointerId)
  }

  function beginSplit1Resize(e: React.PointerEvent) {
    if (isMobile) return
    const w = (e.currentTarget.parentElement as HTMLElement)?.getBoundingClientRect().width ?? 1
    dragRef.current = { kind: 'split1', startX: e.clientX, start: splitA, w }
    ;(e.currentTarget as any).setPointerCapture?.(e.pointerId)
  }

  function beginSplit2Resize(e: React.PointerEvent) {
    if (isMobile) return
    const w = (e.currentTarget.parentElement as HTMLElement)?.getBoundingClientRect().width ?? 1
    dragRef.current = { kind: 'split2', startX: e.clientX, start: splitB, w }
    ;(e.currentTarget as any).setPointerCapture?.(e.pointerId)
  }

  function onPointerMove(e: React.PointerEvent) {
    const d = dragRef.current
    if (!d) return
    if (d.kind === 'sidebar') {
      const next = clamp(d.start + (e.clientX - d.startX), 280, 520)
      setSidebarWidth(next)
      return
    }

    const dx = e.clientX - d.startX
    const ratio = clamp((d.start * d.w + dx) / d.w, 0.15, 0.85)

    if (d.kind === 'split1') {
      // keep split1 < split2
      setSplitA(clamp(ratio, 0.15, splitB - 0.15))
    } else {
      // keep split2 > split1
      setSplitB(clamp(ratio, splitA + 0.15, 0.85))
    }
  }

  function onPointerUp() {
    dragRef.current = null
  }

  const disasmRows = useMemo(() => parseDisasm(disasm), [disasm])

  const ghidraRows = useMemo(() => {
    const lines = ghidraDecomp.split(/\r?\n/)
    return lines.map((line, i) => ({ ln: i + 1, text: line }))
  }, [ghidraDecomp])

  // @ts-ignore - unused after syntax highlighting
  function renderGhidraLine(line: string, ln: number) {
    const matches: Array<{ start: number; end: number; text: string; fid: string }> = []

    // Find address-based function references (FUN_00401000, thunk_FUN_00401000)
    const re1 = /\b(?:FUN_|thunk_FUN_)([0-9A-Fa-f]+)\b/g
    for (const m of line.matchAll(re1)) {
      const start = m.index ?? 0
      const end = start + m[0].length
      const addr = m[1].toLowerCase()
      const fid = entryAddrToId.get(addr) || entryAddrToId.get(`0x${addr}`)
      if (fid) {
        matches.push({ start, end, text: m[0], fid })
      }
    }

    // Find named function references
    if (nameToId.size > 0) {
      const namePattern = Array.from(nameToId.keys())
        .map(name => escapeRegex(name))
        .join('|')
      const re2 = new RegExp(`\\b(${namePattern})\\b`, 'gi')
      for (const m of line.matchAll(re2)) {
        const start = m.index ?? 0
        const end = start + m[0].length
        const fid = nameToId.get(m[1].toLowerCase())
        if (fid) {
          matches.push({ start, end, text: m[0], fid })
        }
      }
    }

    // Sort by position and remove overlaps
    matches.sort((a, b) => a.start - b.start)
    const filtered: typeof matches = []
    let lastEnd = 0
    for (const match of matches) {
      if (match.start >= lastEnd) {
        filtered.push(match)
        lastEnd = match.end
      }
    }

    // Build output
    const out: any[] = []
    let pos = 0
    for (const match of filtered) {
      if (match.start > pos) {
        out.push(line.slice(pos, match.start))
      }
      out.push(
        <span
          key={`${ln}-${match.start}-${match.end}`}
          className='codeLink'
          title={`Jump to ${match.fid}`}
          onClick={() => {
            navigateTo(match.fid, { from: selected ?? undefined, recordEdge: true })
            if (isMobile) setMobileTab('disasm')
          }}
        >
          {displayName(match.fid) || match.text}
        </span>,
      )
      pos = match.end
    }
    if (pos < line.length) {
      out.push(line.slice(pos))
    }

    return out
  }

  const leftW = sidebarCollapsed ? 56 : clamp(sidebarWidth, 280, 800)

  const panesStyle = isMobile
    ? undefined
    : ({ gridTemplateColumns: `${splitA}fr 6px ${splitB - splitA}fr 6px ${1 - splitB}fr` } as any)

  // Keep splitA consistent with disasmCollapsed
  useEffect(() => {
    if (isMobile) return
    if (disasmCollapsed) {
      // Save previous split and collapse to a thin strip
      if (splitA > 0.08) setDisasmSplitPrev(splitA)
      if (splitA !== 0.05) setSplitA(0.05)
    } else {
      // Restore previous split if it was collapsed
      if (splitA < 0.08) setSplitA(disasmSplitPrev || 0.33)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [disasmCollapsed])

  const sidebarStyle = isMobile
    ? ({ width: clamp(sidebarWidth, 280, 500), display: mobileSidebarOpen ? 'flex' : 'none' } as any)
    : ({ width: leftW } as any)

  const selectedStatus = selected ? (index[selected]?.status ?? ai?.status) : undefined
  const selectedProposed = selected ? index[selected]?.proposed_name : undefined

  async function loadCalledRanking() {
    if (!jobId) return
    try {
      const r = await fetch(`${apiBase}/api/jobs/${jobId}/stats/called`)
      const data = await r.json()
      setCalledRanking(data.ranking || [])
    } catch {
      setCalledRanking([])
    }
  }

  async function refreshDebug() {
    if (!jobId) return
    try {
      const s = await fetch(`${apiBase}/api/debug/settings`).then((r) => r.json())
      setDebugSettings(s)
    } catch {
      // ignore
    }

    if (!selected) return

    try {
      const d = await fetch(`${apiBase}/api/jobs/${jobId}/debug/function/${selected}`).then((r) => r.json())
      setDebugData(d)
    } catch {
      setDebugData({ error: 'failed to fetch debug/function' })
    }

    try {
      const q = await fetch(`${apiBase}/api/jobs/${jobId}/debug/queue?n=50`).then((r) => r.json())
      setDebugQueue(q)
    } catch {
      setDebugQueue({ error: 'failed to fetch debug/queue' })
    }

    try {
      const ex = await fetch(`${apiBase}/api/jobs/${jobId}/debug/extract?tail=200`).then((r) => r.json())
      setDebugExtract(ex)
    } catch {
      setDebugExtract({ error: 'failed to fetch debug/extract' })
    }
  }

  useEffect(() => {
    if (!showDebug) return
    refreshDebug()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showDebug, jobId, selected])

  // Live debug logs (SSE)
  useEffect(() => {
    if (!showDebug || !jobId) return
    const es = new EventSource(`${apiBase}/api/jobs/${jobId}/debug/logs/stream?tail=200`)
    setLiveLogsConnected(true)

    es.addEventListener('log', (ev: MessageEvent) => {
      try {
        const obj = JSON.parse(ev.data)
        setLiveLogs((prev) => {
          const next = [...prev, obj]
          return next.length > 500 ? next.slice(next.length - 500) : next
        })
      } catch {
        // ignore
      }
    })

    es.onerror = () => {
      // browser will retry; reflect disconnected briefly
      setLiveLogsConnected(false)
    }

    return () => {
      setLiveLogsConnected(false)
      es.close()
    }
  }, [showDebug, jobId])

  function navigateTo(fid: string, opts?: { from?: string; recordEdge?: boolean }) {
    if (entryOnly && entryFunctionId && fid !== entryFunctionId) setEntryOnly(false)

    if (opts?.recordEdge && opts.from && opts.from !== fid) {
      _setCallEdges((prev) => {
        const cur = prev[opts.from!] ?? []
        if (cur.includes(fid)) return prev
        return { ...prev, [opts.from!]: [...cur, fid] }
      })
    }

    setSelected(fid)

    setNavHistory((prev) => {
      const base = navPos >= 0 ? prev.slice(0, navPos + 1) : prev
      // de-dupe consecutive
      const last = base.length ? base[base.length - 1] : null
      const next = last === fid ? base : [...base, fid]
      setNavPos(next.length - 1)
      return next
    })
  }

  function navBack() {
    setNavPos((p) => {
      const np = Math.max(0, p - 1)
      const fid = navHistory[np]
      if (fid) setSelected(fid)
      return np
    })
  }

  function navForward() {
    setNavPos((p) => {
      const np = Math.min(navHistory.length - 1, p + 1)
      const fid = navHistory[np]
      if (fid) setSelected(fid)
      return np
    })
  }

  function renderPseudocode(text?: string) {
    let src = text ?? ''
    if (!src) return null

    // Remove leading comment block (/* ... */)
    src = src.replace(/^\/\*[\s\S]*?\*\/\s*/m, '')

    const lines = src.split(/\r?\n/)

    // @ts-ignore - unused after syntax highlighting
    const renderLine = (line: string, ln: number) => {
      const matches: Array<{ start: number; end: number; text: string; fid: string }> = []

      // Find address-based function references (sub_00401000, FUN_00401000, function_00401000)
      const re1 = /\b(?:sub|FUN|function)_([0-9A-Fa-f]+)\b/g
      for (const m of line.matchAll(re1)) {
        const start = m.index ?? 0
        const end = start + m[0].length
        const addr = m[1].toLowerCase()
        const fid = entryAddrToId.get(addr) || entryAddrToId.get(`0x${addr}`)
        if (fid) {
          matches.push({ start, end, text: m[0], fid })
        }
      }

      // Find named function references
      if (nameToId.size > 0) {
        const namePattern = Array.from(nameToId.keys())
          .map(name => escapeRegex(name))
          .join('|')
        const re2 = new RegExp(`\\b(${namePattern})\\b`, 'gi')
        for (const m of line.matchAll(re2)) {
          const start = m.index ?? 0
          const end = start + m[0].length
          const fid = nameToId.get(m[1].toLowerCase())
          if (fid) {
            matches.push({ start, end, text: m[0], fid })
          }
        }
      }

      // Sort by position and remove overlaps
      matches.sort((a, b) => a.start - b.start)
      const filtered: typeof matches = []
      let lastEnd = 0
      for (const match of matches) {
        if (match.start >= lastEnd) {
          filtered.push(match)
          lastEnd = match.end
        }
      }

      // Build output
      const out: any[] = []
      let pos = 0
      for (const match of filtered) {
        if (match.start > pos) {
          out.push(line.slice(pos, match.start))
        }
        out.push(
          <span
            key={`${ln}-${match.start}-${match.end}`}
            className='codeLink'
            title={`Jump to ${match.fid}`}
            onClick={() => {
              navigateTo(match.fid, { from: selected ?? undefined, recordEdge: true })
              if (isMobile) setMobileTab('disasm')
            }}
          >
            {displayName(match.fid) || match.text}
          </span>,
        )
        pos = match.end
      }
      if (pos < line.length) {
        out.push(line.slice(pos))
      }

      return out
    }

    return (
      <div className='pseudoCodeLines'>
        {lines.map((line, i) => {
          const ln = i + 1
          // Extract address from line (e.g., "FUN_00401000" or "sub_00401000")
          const addrMatch = line.match(/\b(?:sub|FUN|function)_([0-9A-Fa-f]{8,16})\b/)
          const lineAddr = addrMatch ? addrMatch[1].toLowerCase() : null
          const isHovered = hoveredAddress && lineAddr && lineAddr === hoveredAddress.toLowerCase().replace(/^0x/, '')
          
          return (
            <div
              key={ln}
              className={`pseudoCodeRow ${hoverPseudoLn === ln || isHovered ? 'pseudoCodeRowHover' : ''}`}
              onMouseEnter={() => {
                setHoverPseudoLn(ln)
                if (lineAddr) setHoveredAddress(lineAddr)
              }}
              onMouseLeave={() => {
                setHoverPseudoLn(null)
                setHoveredAddress(null)
              }}
            >
              <div className='pseudoCodeLn'>{ln}</div>
              <div
                className='pseudoCodeContent'
                dangerouslySetInnerHTML={{
                  __html: addFunctionLinks(
                    hljs.highlight(line, { language: 'cpp' }).value,
                    entryAddrToId,
                    nameToId,
                    navigateTo,
                    displayNameById
                  )
                }}
                onClick={(e) => {
                  const target = e.target as HTMLElement
                  if (target.classList.contains('codeLink')) {
                    const fid = target.getAttribute('data-fid')
                    if (fid) {
                      navigateTo(fid, { from: selected ?? undefined, recordEdge: true })
                      if (isMobile) setMobileTab('disasm')
                    }
                  }
                }}
              />
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div className='appRoot' onPointerMove={onPointerMove} onPointerUp={onPointerUp}>
      {/* Sidebar */}
      <aside className={`sidebar ${sidebarCollapsed ? 'sidebarCollapsed' : ''}`} style={sidebarStyle}>
        <div className='sidebarHeader'>
          <div className='brandRow'>
            {!sidebarCollapsed ? <div className='brand'>AutoRE</div> : <div className='brand' aria-hidden='true'>A</div>}
            <div style={{ display: 'flex', gap: 8 }}>
              {isMobile ? (
                <button className='smallBtn' onClick={() => setMobileSidebarOpen(false)}>
                  Close
                </button>
              ) : (
                <button className='smallBtn' onClick={() => setSidebarCollapsed((v) => !v)} title={sidebarCollapsed ? 'Expand' : 'Collapse'}>
                  {sidebarCollapsed ? '»' : '«'}
                </button>
              )}
            </div>
          </div>

          {!sidebarCollapsed ? (
            <>
              <div className='fieldRow'>
                <input
                  className='input'
                  value={jobId}
                  onChange={(e) => setJobId(e.target.value.trim())}
                  placeholder='job_id (sha256)'
                />
                <button className='smallBtn' onClick={() => loadAnalysis(jobId)}>
                  Load
                </button>
              </div>

              <div className='fieldRow'>
                <input
                  id='pathInput'
                  className='input'
                  placeholder='server path (e.g. /samples/a.exe)'
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') createJobByPath((e.target as HTMLInputElement).value)
                  }}
                />
                <button
                  className='smallBtn'
                  onClick={() => {
                    const el = document.getElementById('pathInput') as HTMLInputElement
                    createJobByPath(el.value)
                  }}
                >
                  Open
                </button>
              </div>

              <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                <input
                  type='file'
                  accept='.exe,.dll'
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    if (f) createJobUpload(f)
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10, alignItems: 'center' }}>
                <span className='secondary'>{functions.length} funcs</span>
              </div>

              <div className='secondary' style={{ marginTop: 8 }}>
                Tip: 逆アセンブル中心なら中央ペインを広め、疑似コード中心なら右ペインを広めに。
              </div>
            </>
          ) : null}
        </div>

        {!sidebarCollapsed ? (
          <div className='sidebarBody'>
            <div className='sectionTitleRow'>
              <strong>Recent</strong>
              <span className='badge'>{recentLoading ? '…' : recentJobs.length}</span>
            </div>

            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <input
                className='input'
                value={recentQuery}
                onChange={(e) => setRecentQuery(e.target.value)}
                placeholder='Search jobs: job_id / filename / path'
              />
              <button className='smallBtn' onClick={() => refreshRecentJobs()}>
                Refresh
              </button>
            </div>

            {recentJobs.length ? (
              <div className='functionList' style={{ marginBottom: 14 }}>
                {recentJobs.slice(0, 10).map((j) => {
                  const isExtracting = j.extract_stage && j.extract_stage !== 'done'
                  const statusText = isExtracting
                    ? `re-extract: ${j.extract_stage}`
                    : j.analyzed
                      ? 'analyzed'
                      : 'pending'
                  
                  return (
                    <div
                      key={j.job_id}
                      className={`fnItem ${jobId === j.job_id ? 'fnItemSelected' : ''}`}
                      onClick={async () => {
                        setJobId(j.job_id)
                        await loadAnalysis(j.job_id)
                        if (isMobile) setMobileSidebarOpen(false)
                      }}
                    >
                      <div className='fnMeta'>
                        <div className='fnName'>{(j.original_name || j.job_id).toString()}</div>
                        <div className='fnSub'>
                          <span style={{ fontFamily: 'monospace' }}>{j.job_id.slice(0, 10)}…</span>
                          {isExtracting ? (
                            <span style={{ color: '#ffd766' }}>⚙️ {statusText}</span>
                          ) : (
                            <span>{statusText}</span>
                          )}
                        </div>
                        <div className='secondary' style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {j.source_path || j.sample_path || ''}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        {isExtracting ? (
                          <span className='badge badgeRun'>Processing</span>
                        ) : (
                          <span className='badge'>{j.source_type ?? ''}</span>
                        )}
                        <button
                          className='smallBtn'
                          onClick={(e) => {
                            e.stopPropagation()
                            deleteJob(j.job_id)
                          }}
                          title='Delete job'
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className='secondary' style={{ marginBottom: 14 }}>
                No jobs yet.
              </div>
            )}

            <div className='sectionTitleRow'>
              <strong>Functions</strong>
              <span className='badge'>{filteredFunctions.length}</span>
            </div>

            <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className='input'
                value={fnQuery}
                onChange={(e) => setFnQuery(e.target.value)}
                placeholder='Filter: FUN_ / name / proposed_name'
                style={{ flex: 1, minWidth: 220 }}
              />
              <button
                className={`tinyBtn ${entryOnly ? 'tinyBtnActive' : ''}`}
                onClick={() => setEntryOnly(!entryOnly)}
                title='Entry'
              >
                Entry
              </button>
              <button
                className={`tinyBtn ${winApiOnly ? 'tinyBtnActive' : ''}`}
                onClick={() => setWinApiOnly(!winApiOnly)}
                title='WinAPI'
              >
                WinAPI
              </button>
              <button
                className='tinyBtn'
                onClick={() => {
                  setFnQuery('')
                  setEntryOnly(false)
                  setWinApiOnly(false)
                }}
                title='Clear filters'
              >
                Clear
              </button>
            </div>

            <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className='secondary' style={{ whiteSpace: 'nowrap' }}>
                Sort
              </span>
              <select
                className='input'
                value={sortKey}
                onChange={(e) => setSortKey(e.target.value as SortKey)}
                style={{ padding: '8px 10px' }}
              >
                <option value='entry'>Entry</option>
                <option value='size'>Size</option>
                <option value='name'>Name</option>
                <option value='status'>Status</option>
                <option value='updated'>Updated</option>
              </select>
            </div>

            <div className='functionList'>
              {filteredFunctions.map((f) => {
                const st = index[f.id]?.status
                const upd = index[f.id]?.updated_at
                const proposed = index[f.id]?.proposed_name
                const isEntry = entryFunctionId && f.id === entryFunctionId
                const isWinApi = (f as any).is_winapi || false
                const isExternal = (f as any).is_external || false
                const label = displayName(f.id)

                return (
                  <div
                    key={f.id}
                    className={`fnItem ${selected === f.id ? 'fnItemSelected' : ''}`}
                    onClick={() => {
                      navigateTo(f.id)
                      if (isMobile) {
                        setMobileSidebarOpen(false)
                        setMobileTab('disasm')
                      }
                    }}
                  >
                    <div className='fnMeta'>
                      <div className='fnName'>{label}</div>
                      <div className='fnSub'>
                        <span>{isEntry ? 'entry' : ''}</span>
                        {isWinApi ? <span style={{ color: '#4da3ff' }}>Win API</span> : null}
                        {!isWinApi && isExternal ? <span>external</span> : null}
                        <span>{f.size ? `${f.size} bytes` : ''}</span>
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {proposed && (f.name || f.id) ? `orig: ${f.name ?? f.id}` : ''}
                        </span>
                      </div>
                      {upd ? <div className='secondary'>updated: {fmtJst(upd)} (raw: {upd})</div> : null}
                    </div>
                    <span className={statusBadgeClass(st)}>{st ?? ''}</span>
                  </div>
                )
              })}
            </div>
          </div>
        ) : null}
      </aside>

      {/* Sidebar resizer */}
      {!isMobile ? <div className='sidebarResizer' onPointerDown={beginSidebarResize} /> : null}

      {/* Main */}
      <main className='main'>
        <div className='topbar'>
          <div className='topbarLeft'>
            {isMobile ? (
              <button className='smallBtn' onClick={() => setMobileSidebarOpen(true)}>
                ☰
              </button>
            ) : null}
            <div className='topbarTitle'>
              {(() => {
                const currentJob = recentJobs.find((j) => j.job_id === jobId)
                const isExtracting = currentJob?.extract_stage && currentJob.extract_stage !== 'done'
                
                if (isExtracting) {
                  return (
                    <span style={{ color: '#ffd766' }}>
                      ⚙️ Re-extracting... ({currentJob.extract_stage})
                    </span>
                  )
                }
                
                if (selected) {
                  const dn = displayName(selected)
                  // Avoid overly-long unbroken titles that can force a fixed page width.
                  // Also hide noisy init functions from the title.
                  const showTitle = dn && !dn.startsWith('__dyn_tls_init')
                  return showTitle ? (
                    <>
                      <strong style={{ color: 'rgba(255,255,255,0.92)' }}>{dn}</strong>
                      <span style={{ marginLeft: 10 }}>{selectedFn?.entry ? `@ ${selectedFn.entry}` : ''}</span>
                    </>
                  ) : (
                    <span className='secondary'> </span>
                  )
                }
                
                return <span className='secondary'>Load a job to start.</span>
              })()}
            </div>
          </div>

          <div className='topbarRight'>
            <button className='smallBtn' onClick={navBack} disabled={navPos <= 0} title='Back'>
              ←
            </button>
            <button className='smallBtn' onClick={navForward} disabled={navPos < 0 || navPos >= navHistory.length - 1} title='Forward'>
              →
            </button>

            <button className={`smallBtn ${showDebug ? 'smallBtnActive' : ''}`} onClick={() => setShowDebug(!showDebug)} title='Debug'>
              Debug
            </button>

            <button
              className={`smallBtn ${showRanking ? 'smallBtnActive' : ''}`}
              onClick={() => {
                setShowRanking(true)
                loadCalledRanking()
              }}
              title='Show most-called functions'
            >
              Ranking
            </button>

            <button
              className={`smallBtn ${showCallTree ? 'smallBtnActive' : ''}`}
              onClick={() => setShowCallTree(!showCallTree)}
              title='Show call tree graph'
            >
              Call Tree
            </button>

            <button
              className={`smallBtn ${showCapaModal ? 'smallBtnActive' : ''}`}
              onClick={async () => {
                if (!jobId) return
                try {
                  const st = await fetch(`${apiBase}/api/tools/capa/status`).then((r) => r.json())
                  if (!st?.installed) {
                    // Best-effort install
                    const res = await fetch(`${apiBase}/api/tools/capa/install`, { method: 'POST' }).then((r) => r.json())
                    if (!res?.installed) {
                      alert(`CAPA is not installed.\n\nInstaller output:\n${res?.output || res?.error || 'unknown error'}`)
                      return
                    }
                    alert('CAPA installed. Please Re-extract the current job to generate capa.json.')
                  }
                  setShowCapaModal(true)
                } catch (e: any) {
                  alert(`CAPA check/install failed: ${String(e?.message || e)}`)
                }
              }}
              disabled={!jobId}
              title='Show CAPA malware capability detection results'
            >
              CAPA
            </button>

            <button
              className={`smallBtn ${showXrefs ? 'smallBtnActive' : ''}`}
              onClick={() => setShowXrefs(true)}
              disabled={!selectedFn}
              title='Show xrefs (calls in/out) for selected function'
            >
              Xrefs
            </button>

            <button
              className={`smallBtn ${showCFG ? 'smallBtnActive' : ''}`}
              onClick={() => {
                if (!jobId || !selected) return
                setCfgRootId(selected)
                setShowCFG(true)
                loadCFG(jobId, selected, cfgDepth)
              }}
              disabled={!jobId || !selected}
              title='Show calls_out graph (depth=3)'
            >
              CFG
            </button>

            <button
              className='smallBtn'
              onClick={() => {
                setStringQuery('')
                setStringMinLen(0)
                setStringMaxLen(0)
                setShowStrings(true)
              }}
              disabled={!analysis?.strings?.length}
              title='Show extracted strings'
            >
              Strings
              {analysis?.strings?.length ? <span className='badge' style={{ marginLeft: 8 }}>{analysis.strings.length}</span> : null}
            </button>

            {/* moved to Settings */}

            <button
              className={`smallBtn ${showMainCandidates ? 'smallBtnActive' : ''}`}
              onClick={() => setShowMainCandidates(true)}
              disabled={!jobId || !functions.length}
              title='Show main candidates + reasons'
            >
              Main candidates
            </button>

            {mainGuess?.function_id ? (
              <span
                className={`badge ${selected === mainGuess.function_id ? 'badgeOk' : ''}`}
                title={mainGuess.reason ?? ''}
                style={{ cursor: 'pointer' }}
                onClick={() => setShowMainCandidates(true)}
              >
                Main: {mainGuess.function_id}
              </span>
            ) : null}
            {selectedProposed ? <span className='badge'>AI: {selectedProposed}</span> : null}
            {selected ? <span className={statusBadgeClass(selectedStatus)}>{selectedStatus ?? ''}</span> : null}

            {/* provider/model configured in Settings */}
            {providerChoice === 'openai' ? (
              <input
                className='input'
                value={openaiBaseUrl}
                onChange={(e) => setOpenaiBaseUrl(e.target.value)}
                placeholder='OPENAI_BASE_URL (e.g. http://host:8000/v1)'
                style={{ padding: '6px 8px', width: 260 }}
                title='OpenAI Base URL (vLLM endpoint). /v1付きOK'
              />
            ) : null}

            {jobId ? (
              <button className='smallBtn' onClick={() => findMain(jobId)}>
                Find main
              </button>
            ) : null}
            {jobId ? (
              <button className='smallBtn' onClick={() => requestReextract(jobId)} title='Re-run Ghidra extract (needed to generate Ghidra decompiler output)'>
                Re-extract
              </button>
            ) : null}
            {selected && (
              <>
                <button
                  className='smallBtn'
                  onClick={async () => {
                    // optimistic UI
                    setAi({ function_id: selected, status: 'queued' })
                    setIndex((prev) => ({ ...prev, [selected]: { ...(prev[selected] || {}), status: 'queued' } }))
                    await requestDecompile(jobId, selected, { force: true })
                  }}
                  disabled={ai?.status === 'queued' || ai?.status === 'running'}
                >
                  Run / Re-run
                </button>

                <button
                  className='smallBtn'
                  onClick={async () => {
                    if (!jobId || !selected) return
                    const fd = new FormData()
                    if (providerChoice) fd.set('provider', providerChoice)

                    const effectiveModel =
                      modelChoice || (providerChoice === 'openai' ? openaiDefaultModel : anthropicDefaultModel) || ''
                    if (effectiveModel) fd.set('model', effectiveModel)

                    if (providerChoice === 'openai') {
                      if (openaiBaseUrl.trim()) fd.set('openai_base_url', openaiBaseUrl.trim())
                      if (openaiApiKey.trim()) fd.set('openai_api_key', openaiApiKey.trim())
                      if (openaiApiMode.trim()) fd.set('openai_api_mode', openaiApiMode.trim())
                      if (openaiReasoning.trim()) fd.set('openai_reasoning', openaiReasoning.trim())
                    }

                    await fetch(`${apiBase}/api/jobs/${jobId}/functions/${selected}/summarize`, { method: 'POST', body: fd })
                    // refresh
                    window.setTimeout(() => loadFuncSummary(jobId, selected), 600)
                  }}
                  disabled={!jobId || !selected}
                  title='Generate/update summary_ja for the selected function'
                >
                  Summarize
                </button>

                <button
                  className={`smallBtn ${showExeSummary ? 'smallBtnActive' : ''}`}
                  onClick={() => {
                    setShowExeSummary((v) => !v)
                    if (jobId) {
                      loadExeSummary(jobId)
                      loadExeSummaryLogs(jobId)
                    }
                  }}
                  disabled={!jobId}
                  title='Show / update EXE-level summary'
                >
                  EXE Summary
                </button>
              </>
            )}

            <button className='smallBtn' onClick={() => setShowSettings(true)} title='Settings'>
              Settings
            </button>
          </div>
        </div>

        {/* Mobile tabs */}
        {isMobile ? (
          <div className='topbar' style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <button 
                className={`smallBtn ${mobileTab === 'disasm' ? 'smallBtnActive' : ''}`}
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setMobileTab('disasm')}
              >
                Disasm
              </button>
              <button 
                className={`smallBtn ${mobileTab === 'ghidra' ? 'smallBtnActive' : ''}`}
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setMobileTab('ghidra')}
              >
                Ghidra
              </button>
              <button 
                className={`smallBtn ${mobileTab === 'ai' ? 'smallBtnActive' : ''}`}
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setMobileTab('ai')}
              >
                AI
              </button>
            </div>
            {selected && index[selected]?.status === 'ok' ? <span className='badge badgeOk'>Cached</span> : null}
          </div>
        ) : null}

        <div className='panes' style={panesStyle}>
          {/* Disasm */}
          <section
            className={`pane ${!isMobile && disasmCollapsed ? 'paneCollapsed' : ''}`}
            style={isMobile && mobileTab !== 'disasm' ? { display: 'none' } : undefined}
          >
            <div className='paneHeader'>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  className='tinyBtn'
                  title={disasmCollapsed ? 'Expand Disassembly' : 'Collapse Disassembly'}
                  onClick={(e) => {
                    e.stopPropagation()
                    setDisasmCollapsed(!disasmCollapsed)
                  }}
                  style={{ padding: '2px 8px' }}
                >
                  {disasmCollapsed ? '▸' : '◂'}
                </button>
                <span>Disassembly</span>
                {disasmRows.length > 0 && <span className='secondary' style={{ fontSize: 12 }}>({disasmRows.length} lines)</span>}
              </h4>
              {!disasmCollapsed ? <span className='sub'>{selectedFn?.entry ? `@ ${selectedFn.entry}` : selected ?? ''}</span> : <span className='sub' />}
            </div>
            <div className='paneBody'>
              <div className='disasm'>
                {disasmRows.length ? (
                  disasmRows.map((r) => {
                    const normAddr = r.addr.toLowerCase().replace(/^0x/, '')
                    const isHovered = hoveredAddress && normAddr === hoveredAddress.toLowerCase().replace(/^0x/, '')
                    return (
                      <div
                        key={r.ln}
                        ref={(el) => {
                          if (el && r.addr) {
                            disasmRowRefs.current.set(normAddr, el)
                          }
                        }}
                        className={`disasmRow ${hoverDisasmLn === r.ln || isHovered ? 'disasmRowHover' : ''}`}
                        onMouseEnter={() => {
                          setHoverDisasmLn(r.ln)
                          if (r.addr) setHoveredAddress(normAddr)
                        }}
                        onMouseLeave={() => {
                          setHoverDisasmLn(null)
                          setHoveredAddress(null)
                        }}
                      >
                        <div className='disasmLn'>{r.ln}</div>
                        <div className='disasmAddr'>{r.addr}</div>
                        <div
                          className='disasmInst'
                          dangerouslySetInnerHTML={{
                            __html: hljs.highlight(r.inst, { language: 'x86asm' }).value
                          }}
                        />
                      </div>
                    )
                  })
                ) : (
                  <div className='secondary'>No disassembly yet.</div>
                )}
              </div>
            </div>
          </section>

          {/* Split resizer */}
          {!isMobile ? <div className='resizer' onPointerDown={beginSplit1Resize} /> : null}

          {/* Ghidra decompiler output */}
          <section className='pane' style={isMobile && mobileTab !== 'ghidra' ? { display: 'none' } : undefined}>
            <div className='paneHeader'>
              <h4>
                Ghidra
                {ghidraRows.length > 0 && <span className='secondary' style={{ fontSize: 12, marginLeft: 8 }}>({ghidraRows.length} lines)</span>}
              </h4>
              <span className='sub'>{displayName(selected) || ''}</span>
            </div>
            <div className='paneBody'>
              {ghidraDecomp ? (
                <div className='ghidraDecomp'>
                  {ghidraRows.map((r) => {
                    // Extract address from line (e.g., "FUN_00401000" or "0x00401000")
                    const addrMatch = r.text.match(/\b(?:FUN_|thunk_FUN_)?([0-9A-Fa-f]{8,16})\b/)
                    const lineAddr = addrMatch ? addrMatch[1].toLowerCase() : null
                    const isHovered = hoveredAddress && lineAddr && lineAddr === hoveredAddress.toLowerCase().replace(/^0x/, '')
                    
                    return (
                      <div
                        key={r.ln}
                        className={`ghidraRow ${isHovered ? 'ghidraRowHover' : ''}`}
                        onMouseEnter={() => {
                          if (lineAddr) setHoveredAddress(lineAddr)
                        }}
                        onMouseLeave={() => {
                          setHoveredAddress(null)
                        }}
                      >
                        <div className='ghidraLn'>{r.ln}</div>
                        <div
                          className='ghidraContent'
                          dangerouslySetInnerHTML={{
                            __html: addFunctionLinks(
                              hljs.highlight(r.text, { language: 'cpp' }).value,
                              entryAddrToId,
                              nameToId,
                              navigateTo,
                              displayNameById
                            )
                          }}
                          onClick={(e) => {
                            const target = e.target as HTMLElement
                            if (target.classList.contains('codeLink')) {
                              const fid = target.getAttribute('data-fid')
                              if (fid) {
                                navigateTo(fid, { from: selected ?? undefined, recordEdge: true })
                                if (isMobile) setMobileTab('disasm')
                              }
                            }
                          }}
                        />
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className='secondary'>No Ghidra decompile output (re-extract required).</div>
              )}
            </div>
          </section>

          {/* Split resizer */}
          {!isMobile ? <div className='resizer' onPointerDown={beginSplit2Resize} /> : null}

          {/* AI pseudocode */}
          <section className='pane' style={isMobile && mobileTab !== 'ai' ? { display: 'none' } : undefined}>
            <div className='paneHeader'>
              <h4>
                AI
                {(() => {
                  const code = ai?.pseudocode || ''
                  const lineCount = code ? code.split('\n').length : 0
                  return lineCount > 0 ? <span className='secondary' style={{ fontSize: 12, marginLeft: 8 }}>({lineCount} lines)</span> : null
                })()}
              </h4>
              <span className='sub'>
                {selected ? (index[selected]?.status || ai?.status || '') : ai?.status || ''}
                {selected && lastDecompileFid === selected && lastDecompileResp?.status && lastDecompileResp.status !== (index[selected]?.status || ai?.status)
                  ? ` · last POST=${lastDecompileResp.status}`
                  : ''}
              </span>
            </div>
            <div className='paneBody'>
              {showDebug ? (
                <details className='fold' open>
                  <summary className='foldSummary'>Debug</summary>
                  <div className='foldBody'>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                      <button className='smallBtn' onClick={refreshDebug} disabled={!jobId || !selected}>
                        Refresh debug
                      </button>
                      <span className='badge'>job: {jobId ? jobId.slice(0, 8) : '-'}</span>
                      <span className='badge'>fid: {selected ?? '-'}</span>
                      <span className='badge'>ui model: {modelChoice || 'default'}</span>
                      {ai?.model ? <span className='badge'>result model: {ai.model}</span> : null}
                      {ai?.updated_at ? <span className='badge'>updated: {fmtJst(ai.updated_at)} (raw: {ai.updated_at})</span> : null}
                      {selected ? (
                        <span className='badge'>
                          stage: {index[selected]?.status || ai?.status || '-'}
                          {index[selected]?.queued_at ? ` · queued_at=${fmtJst(index[selected]?.queued_at)} (raw:${index[selected]?.queued_at})` : ''}
                          {index[selected]?.started_at ? ` · started_at=${fmtJst(index[selected]?.started_at)} (raw:${index[selected]?.started_at})` : ''}
                          {index[selected]?.finished_at ? ` · finished_at=${fmtJst(index[selected]?.finished_at)} (raw:${index[selected]?.finished_at})` : ''}
                          {typeof index[selected]?.api_ms === 'number' ? ` · api_ms=${index[selected]?.api_ms}` : ''}
                          {typeof index[selected]?.total_ms === 'number' ? ` · total_ms=${index[selected]?.total_ms}` : ''}
                        </span>
                      ) : null}
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 10 }}>
                      <div>
                        <div className='secondary' style={{ marginBottom: 6, display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                          <span>
                            Live API logs (Anthropic)
                            {liveLogsConnected ? ' · connected' : ' · reconnecting…'}
                          </span>
                          <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <input
                              type='checkbox'
                              checked={liveLogsFilterSelected}
                              onChange={(e) => setLiveLogsFilterSelected(e.target.checked)}
                            />
                            only selected
                          </label>
                        </div>

                        <div className='logBox'>
                          {liveLogs
                            .filter((x) => (!liveLogsFilterSelected ? true : x?.function_id === selected))
                            .map((x, i) => (
                              <div key={i} className='logRow'>
                                <span className='logTs'>{fmtJst(x?.ts) || String(x?.ts ?? '')}</span>
                                <span className='logEvt'>{String(x?.event ?? '')}</span>
                                <span className='logMsg'>
                                  {x?.model ? `model=${x.model} ` : ''}
                                  {x?.status_code ? `status=${x.status_code} ` : ''}
                                  {typeof x?.api_ms === 'number' ? `api_ms=${x.api_ms} ` : ''}
                                  {typeof x?.total_ms === 'number' ? `total_ms=${x.total_ms} ` : ''}
                                  {x?.usage?.input_tokens ? `in_tok=${x.usage.input_tokens} ` : ''}
                                  {x?.usage?.output_tokens ? `out_tok=${x.usage.output_tokens} ` : ''}
                                  {x?.usage?.input_tokens && x?.usage?.output_tokens ? `total_tok=${x.usage.input_tokens + x.usage.output_tokens} ` : ''}
                                  {x?.error ? `error=${x.error}` : ''}
                                </span>
                              </div>
                            ))}
                        </div>
                      </div>
                      <div>
                        <div className='secondary' style={{ marginBottom: 6 }}>
                          Last decompile POST response
                        </div>
                        <JsonPre value={{ fid: lastDecompileFid, ...lastDecompileResp }} />
                      </div>

                      <div>
                        <div className='secondary' style={{ marginBottom: 6 }}>
                          /api/jobs/{'{job}'}/debug/function/{'{fid}'}
                        </div>
                        <JsonPre value={debugData} />
                      </div>

                      <div>
                        <div className='secondary' style={{ marginBottom: 6 }}>
                          /api/jobs/{'{job}'}/debug/extract
                        </div>
                        <JsonPre value={debugExtract} />
                      </div>

                      <div>
                        <div className='secondary' style={{ marginBottom: 6 }}>
                          /api/jobs/{'{job}'}/debug/queue
                        </div>
                        <JsonPre value={debugQueue} />
                      </div>

                      <div>
                        <div className='secondary' style={{ marginBottom: 6 }}>
                          /api/debug/settings
                        </div>
                        <JsonPre value={debugSettings} />
                      </div>
                    </div>
                  </div>
                </details>
              ) : null}
              
              

              {/* Function summary (always visible if available; independent from AI decompile status) */}
              {selected && ((funcSummary as any)?.summary_ja || (ai as any)?.summary_ja) ? (
                <details className='fold' open style={{ marginBottom: '12px' }}>
                  <summary
                    className='foldSummary'
                    style={{
                      padding: '8px 12px',
                      background: 'rgba(255, 215, 0, 0.08)',
                      border: '1px solid rgba(255, 215, 0, 0.2)',
                      borderRadius: '10px',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'rgba(255, 215, 0, 0.9)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: 10,
                      alignItems: 'center',
                    }}
                  >
                    <span>📝 概要</span>
                    <span className='secondary' style={{ fontSize: 11 }}>
                      {(ai as any)?.summary_ja ? 'source: decompile' : 'source: summarize'}
                    </span>
                  </summary>
                  <div
                    className='foldBody'
                    style={{
                      padding: '12px 16px',
                      background: 'rgba(255, 215, 0, 0.08)',
                      border: '1px solid rgba(255, 215, 0, 0.2)',
                      borderTop: 'none',
                      borderRadius: '0 0 10px 10px',
                      lineHeight: '1.6',
                      color: 'rgba(255,255,255,0.85)',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {(ai as any)?.summary_ja || (funcSummary as any)?.summary_ja}
                  </div>
                </details>
              ) : null}

              {ai?.status === 'ok' ? (
                <>
                  <div className='pseudoTitle'>
                    <div className='pseudoName'>{ai.proposed_name ?? displayName(selected)}</div>
                    <div className='pseudoSig'>{ai.signature ?? ''}</div>
                  </div>

                  <div style={{ height: 10 }} />
                  <div className='codeBlock'>{renderPseudocode(ai.pseudocode)}</div>
                </>
              ) : ai?.status === 'error' ? (
                <div className='codeBlock'>{ai.error}</div>
              ) : (
                <div className='secondary'>生成待ち…（Run / Re-run で開始できます）</div>
              )}
            </div>
          </section>



        </div>
      </main>

      {/* Desktop Call Tree Modal */}
      {!isMobile && showCallTree && analysis?.functions && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowCallTree(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '95vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Call Tree</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  Function call graph
                </div>
              </div>
              <button
                className='smallBtn'
                onClick={() => setShowCallTree(false)}
                style={{ fontSize: 20, padding: '4px 12px' }}
              >
                ✕
              </button>
            </div>
            <div style={{ flex: 1, overflow: 'auto', padding: 20 }}>
              <CallTreeView
                functions={analysis.functions}
                selected={selected}
                onNavigate={(fid) => {
                  navigateTo(fid)
                  setShowCallTree(false)
                }}
                displayName={displayName}
              />
            </div>
          </div>
        </div>
      )}

      {/* Ranking Modal */}
      {!isMobile && showRanking ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1075,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowRanking(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '85vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Most Called Functions ({calledRanking.length})</h3>
                <div className='secondary' style={{ marginTop: 4, fontSize: 12 }}>click a row to jump</div>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button className='smallBtn' onClick={loadCalledRanking} disabled={!jobId}>
                  Refresh
                </button>
                <button className='smallBtn' onClick={() => setShowRanking(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                  ✕
                </button>
              </div>
            </div>

            <div style={{ padding: 10, overflow: 'auto' }}>
              {calledRanking.length ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {calledRanking.slice(0, 200).map((item, i) => (
                    <div
                      key={item.function_id}
                      className='fnItem'
                      onClick={() => {
                        navigateTo(item.function_id)
                        if (isMobile) setMobileTab('disasm')
                        setShowRanking(false)
                      }}
                      style={{ cursor: 'pointer' }}
                    >
                      <div className='fnMeta'>
                        <div className='fnName'>
                          #{i + 1} {displayName(item.function_id) || item.name || item.function_id}
                        </div>
                        <div className='fnSub'>
                          <span>{item.call_count} calls</span>
                          <span>{item.entry ? `@ ${item.entry}` : ''}</span>
                          <span>{item.size ? `${item.size} bytes` : ''}</span>
                        </div>
                      </div>
                      <span className='badge'>{item.call_count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className='secondary' style={{ padding: 20 }}>No call data available.</div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {/* CAPA Modal */}
      {showCapaModal ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1080,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowCapaModal(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '95vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>CAPA</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  Malware Capability Detection
                </div>
              </div>
              <button className='smallBtn' onClick={() => setShowCapaModal(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                ✕
              </button>
            </div>

            <div style={{ flex: 1, overflow: 'auto', padding: 20 }}>
              {!capaData ? (
                <div style={{ padding: 20, textAlign: 'center', color: 'rgba(255,255,255,0.4)' }}>Loading CAPA results...</div>
              ) : capaData.error ? (
                <div style={{ padding: 20, color: 'rgba(255,100,100,0.8)' }}>
                  <div>⚠️ CAPA not available</div>
                  <div style={{ fontSize: '13px', marginTop: 8 }}>{capaData.error}</div>
                  <div style={{ fontSize: '12px', marginTop: 12, color: 'rgba(255,255,255,0.5)' }}>
                    Note: after installing CAPA or updating server, re-run re-extract to regenerate capa.json.
                  </div>
                </div>
              ) : capaData.rules ? (
                <div>
                  <div style={{ padding: '12px 0px', borderBottom: '1px solid rgba(255,255,255,0.06)', marginBottom: 16 }}>
                    <div style={{ fontSize: '14px', fontWeight: 500, marginBottom: 8 }}>
                      {Object.keys(capaData.rules).length} capabilities detected
                    </div>
                    {capaData.meta?.analysis && (
                      <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)' }}>
                        {capaData.meta.analysis.format} · {capaData.meta.analysis.arch} · {capaData.meta.analysis.os}
                      </div>
                    )}
                  </div>

                  {Object.entries(capaData.rules).map(([ruleName, ruleData]: [string, any]) => (
                    <details key={ruleName} className='fold' style={{ marginBottom: 12 }}>
                      <summary className='foldSummary' style={{ fontWeight: 500 }}>
                        ✓ {ruleName}
                        {ruleData.namespace && (
                          <span style={{ fontSize: '11px', color: 'rgba(255,255,255,0.4)', marginLeft: 8 }}>{ruleData.namespace}</span>
                        )}
                      </summary>
                      <div className='foldBody'>
                        {ruleData.matches && ruleData.matches.length > 0 && (
                          <div style={{ marginBottom: 12 }}>
                            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginBottom: 6 }}>
                              Matches ({ruleData.matches.length}):
                            </div>
                            {ruleData.matches.slice(0, 10).map((match: any, idx: number) => {
                              const firstLoc = match && match[0]
                              const addrValue = firstLoc?.type === 'absolute' && firstLoc?.value ? firstLoc.value : null
                              const addr = addrValue
                                ? `0x${addrValue.toString(16).toUpperCase()}`
                                : firstLoc?.type === 'no address'
                                  ? '(file-level)'
                                  : 'N/A'

                              const matchingFunc = addrValue != null && analysis?.functions
                                ? analysis.functions.find((f: any) => {
                                    // Compare numerically to support both 32-bit (8 hex) and 64-bit (9-16 hex) addresses.
                                    const fEntryStr = String(f.entry || '').trim().toLowerCase().replace(/^0x/, '')
                                    const fEntryVal = Number.parseInt(fEntryStr, 16)
                                    if (!Number.isFinite(fEntryVal)) return false
                                    return fEntryVal === addrValue
                                  })
                                : null
                              const functionId = matchingFunc?.id || null

                              return (
                                <div key={idx} style={{ fontSize: '12px', fontFamily: 'monospace', marginBottom: 4 }}>
                                  • {functionId ? (
                                    <button
                                      className='smallBtn'
                                      style={{ padding: '2px 6px', fontSize: '12px', fontFamily: 'monospace', cursor: 'pointer' }}
                                      onClick={() => {
                                        navigateTo(functionId)
                                        setShowCapaModal(false)
                                      }}
                                      title={`Jump to ${functionId}`}
                                    >
                                      {addr}
                                    </button>
                                  ) : (
                                    <span>{addr}</span>
                                  )}
                                </div>
                              )
                            })}
                            {ruleData.matches.length > 10 && (
                              <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.4)', marginTop: 4 }}>
                                ... and {ruleData.matches.length - 10} more
                              </div>
                            )}
                          </div>
                        )}

                        {ruleData.attack && ruleData.attack.length > 0 && (
                          <div>
                            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginBottom: 6 }}>ATT&CK:</div>
                            {ruleData.attack.map((att: any, idx: number) => (
                              <div key={idx} style={{ fontSize: '12px', marginBottom: 4 }}>
                                • {att.id}: {att.tactic || att.technique || ''}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </details>
                  ))}
                </div>
              ) : (
                <div style={{ padding: 20, textAlign: 'center', color: 'rgba(255,255,255,0.4)' }}>No capabilities detected</div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {/* Xrefs Modal (calls in/out) */}
      {showMainCandidates ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1090,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowMainCandidates(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '90vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Main candidates</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  Click to jump. Scores are heuristic.
                </div>
              </div>
              <button className='smallBtn' onClick={() => setShowMainCandidates(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                ✕
              </button>
            </div>

            <div style={{ padding: 20, overflow: 'auto' }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
                <button
                  className='smallBtn'
                  onClick={async () => {
                    if (jobId) await findMain(jobId)
                  }}
                  disabled={!jobId}
                >
                  Re-run Find main
                </button>
                {mainGuess?.function_id ? (
                  <span className='badge badgeOk' title={mainGuess.reason ?? ''}>
                    picked: {mainGuess.function_id}
                  </span>
                ) : (
                  <span className='badge'>picked: (none)</span>
                )}
                {mainGuessError ? <span className='badge badgeErr'>error: {mainGuessError}</span> : null}
              </div>

              <div className='functionList'>
                {mainCandidates.map((c) => (
                  <div
                    key={`mc-${c.id}`}
                    className={`fnItem ${selected === c.id ? 'fnItemSelected' : ''}`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => {
                      navigateTo(c.id)
                      setShowMainCandidates(false)
                    }}
                    title={c.reasons.join(' | ')}
                  >
                    <div className='fnMeta'>
                      <div className='fnName'>
                        {c.label}
                        <span className='secondary' style={{ marginLeft: 10, fontFamily: 'monospace' }}>
                          {c.id}
                        </span>
                      </div>
                      <div className='fnSub'>
                        <span>score {c.score.toFixed(2)}</span>
                        {c.reasons.length ? <span>理由: {c.reasons.join(' / ')}</span> : null}
                      </div>
                    </div>
                  </div>
                ))}
                {!mainCandidates.length ? <div className='secondary'>No candidates.</div> : null}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {showSettings ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1080,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowSettings(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '85vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Settings</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  Provider / Model / OpenAI endpoint / Find main automation
                </div>
              </div>
              <button className='smallBtn' onClick={() => setShowSettings(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                ✕
              </button>
            </div>

            <div style={{ padding: 20, overflow: 'auto' }}>
              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>AI Provider</strong>
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginBottom: 14 }}>
                <label className='secondary'>Provider</label>
                <select className='input' value={providerChoice} onChange={(e) => setProviderChoice(e.target.value)} style={{ padding: '6px 8px', width: 160 }}>
                  <option value='anthropic'>anthropic</option>
                  <option value='openai'>openai</option>
                </select>

                <label className='secondary'>Model</label>
                <input
                  className='input'
                  list='modelPresets'
                  value={modelChoice}
                  onChange={(e) => setModelChoice(e.target.value)}
                  placeholder='(empty=default)'
                  style={{ padding: '6px 8px', width: 240 }}
                />
                <datalist id='modelPresets'>
                  {/* OpenAI/internal */}
                  <option value='gpt-oss-high' />
                  <option value='gpt-oss-medium' />
                  <option value='gpt-oss-low' />
                  <option value='gpt-oss-120b' />
                  {/* Anthropic */}
                  <option value='claude-sonnet-4-5' />
                  <option value='claude-opus-4-5' />
                </datalist>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>Chat Assistant</strong>
                <span className='badge'>UI</span>
              </div>
              <div className='secondary' style={{ marginBottom: 8 }}>
                チャットで使う Provider / Model（/api/chat）
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginBottom: 18 }}>
                <label className='secondary'>Provider</label>
                <select className='input' value={chatProvider} onChange={(e) => setChatProvider(e.target.value as any)} style={{ padding: '6px 8px', width: 200 }}>
                  <option value='openai'>OpenAI-compatible</option>
                  <option value='anthropic'>Anthropic</option>
                </select>

                <label className='secondary'>Model</label>
                <input
                  className='input'
                  list='modelPresets'
                  value={chatModel}
                  onChange={(e) => setChatModel(e.target.value)}
                  placeholder='(empty=default)'
                  style={{ padding: '6px 8px', width: 240 }}
                />

                <button
                  className='smallBtn'
                  onClick={() => {
                    // convenience: copy settings model/provider into chat
                    setChatProvider(providerChoice === 'anthropic' ? 'anthropic' : 'openai')
                    setChatModel(modelChoice)
                  }}
                  title='Copy from AI Provider section'
                >
                  Copy from above
                </button>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>OpenAI-compatible endpoint (internal)</strong>
              </div>
              <div className='secondary' style={{ marginBottom: 8 }}>
                Base URLは <span style={{ fontFamily: 'monospace' }}>http://host:port/v1</span> のように <span style={{ color: '#ffd766' }}>/v1付き</span> でもOK。認証不要ならAPI keyは空でOK。
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginBottom: 10 }}>
                <label className='secondary'>OPENAI_BASE_URL</label>
                <input className='input' value={openaiBaseUrl} onChange={(e) => setOpenaiBaseUrl(e.target.value)} placeholder='http://host:8000/v1' style={{ padding: '6px 8px', width: 360 }} />
                <label className='secondary'>OPENAI_API_KEY (optional)</label>
                <input className='input' value={openaiApiKey} onChange={(e) => setOpenaiApiKey(e.target.value)} placeholder='(empty OK)' style={{ padding: '6px 8px', width: 240 }} />
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginBottom: 18 }}>
                <label className='secondary'>API</label>
                <select className='input' value={openaiApiMode} onChange={(e) => setOpenaiApiMode(e.target.value)} style={{ padding: '6px 8px', width: 180 }}>
                  <option value='chat'>chat.completions</option>
                  <option value='responses'>responses</option>
                </select>

                <label className='secondary'>reasoning</label>
                <select className='input' value={openaiReasoning} onChange={(e) => setOpenaiReasoning(e.target.value)} style={{ padding: '6px 8px', width: 180 }}>
                  <option value=''>default</option>
                  <option value='low'>low</option>
                  <option value='medium'>medium</option>
                  <option value='high'>high</option>
                </select>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>Find main automation</strong>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', marginBottom: 18 }}>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type='checkbox' checked={autoAiOnFindMain} onChange={(e) => setAutoAiOnFindMain(e.target.checked)} />
                  Find main後に上位候補を自動でAI decompileに投げる
                </label>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  Top N
                  <input
                    className='input'
                    type='number'
                    min={0}
                    max={10}
                    value={autoAiTopN}
                    onChange={(e) => setAutoAiTopN(Number(e.target.value || 0))}
                    style={{ padding: '6px 8px', width: 90 }}
                  />
                </label>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>UI toggles</strong>
              </div>
              <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center', marginBottom: 18 }}>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type='checkbox' checked={autoRunOnSelect} onChange={(e) => setAutoRunOnSelect(e.target.checked)} />
                  auto-run (selectでAI実行)
                </label>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type='checkbox' checked={multiStageEnabled} onChange={(e) => setMultiStageEnabled(e.target.checked)} />
                  multi-stage
                </label>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type='checkbox' checked={entryOnly} onChange={(e) => setEntryOnly(e.target.checked)} />
                  entry only
                </label>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>Guardrail (retry)</strong>
                <span className='badge'>worker</span>
              </div>
              <div className='secondary' style={{ marginBottom: 8 }}>
                response_format無しのOpenAI互換API向け。満足なJSON/疑似コードが出るまでリトライします（上限あり）。
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', marginBottom: 18 }}>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  max attempts
                  <input
                    className='input'
                    type='number'
                    min={1}
                    max={10}
                    value={guardrailMaxAttempts}
                    onChange={(e) => setGuardrailMaxAttempts(Number(e.target.value || 1))}
                    style={{ padding: '6px 8px', width: 110 }}
                  />
                </label>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  min confidence
                  <input
                    className='input'
                    type='number'
                    step='0.05'
                    min={0}
                    max={1}
                    value={guardrailMinConfidence}
                    onChange={(e) => setGuardrailMinConfidence(Number(e.target.value || 0))}
                    style={{ padding: '6px 8px', width: 140 }}
                  />
                </label>
              </div>

              <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                <strong>Provider defaults</strong>
              </div>
              <div className='secondary' style={{ marginBottom: 8 }}>
                Model欄が空のときに使うデフォルトモデルです（環境変数の代わりにUIで上書き）。
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', marginBottom: 10 }}>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  OPENAI_MODEL_DEFAULT
                  <input
                    className='input'
                    list='openaiDefaultModelPresets'
                    value={openaiDefaultModel}
                    onChange={(e) => setOpenaiDefaultModel(e.target.value)}
                    style={{ padding: '6px 8px', width: 240 }}
                  />
                  <datalist id='openaiDefaultModelPresets'>
                    <option value='gpt-oss-high' />
                    <option value='gpt-oss-medium' />
                    <option value='gpt-oss-low' />
                    <option value='gpt-oss-120b' />
                  </datalist>
                </label>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  ANTHROPIC_MODEL_DEFAULT
                  <input className='input' value={anthropicDefaultModel} onChange={(e) => setAnthropicDefaultModel(e.target.value)} style={{ padding: '6px 8px', width: 260 }} />
                </label>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {showCFG ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1090,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowCFG(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '95vw',
              width: '100%',
              height: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 12,
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>CFG (calls_out)</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  root: {cfgRootId ? displayName(cfgRootId) : selected ? displayName(selected) : '-'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <label className='secondary' style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  depth
                  <select
                    className='input'
                    value={cfgDepth}
                    onChange={(e) => {
                      const d = Number(e.target.value)
                      setCfgDepth(d)
                      const root = cfgRootId || selected
                      if (jobId && root) loadCFG(jobId, root, d)
                    }}
                    style={{ padding: '6px 8px', width: 90 }}
                  >
                    <option value={1}>1</option>
                    <option value={2}>2</option>
                    <option value={3}>3</option>
                  </select>
                </label>
                <button
                  className='smallBtn'
                  onClick={() => {
                    const root = cfgRootId || selected
                    if (jobId && root) loadCFG(jobId, root, cfgDepth)
                  }}
                  disabled={!jobId || !selected}
                >
                  Refresh
                </button>
                <button className='smallBtn' onClick={() => setShowCFG(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                  ✕
                </button>
              </div>
            </div>

            <div style={{ padding: 10, flex: 1, minHeight: 0 }}>
              {cfgLoading ? (
                <div className='secondary' style={{ padding: 20 }}>Loading…</div>
              ) : cfgError ? (
                <div style={{ padding: 20, color: 'rgba(255,96,96,0.9)', whiteSpace: 'pre-wrap' }}>{cfgError}</div>
              ) : !cfgData || (cfgData as any)?.status === 'analyzing' ? (
                <div className='secondary' style={{ padding: 20 }}>No graph data yet.</div>
              ) : (
                <div style={{ width: '100%', height: '100%' }}>
                  <ReactFlow
                    nodes={cfgNodes}
                    edges={cfgEdges}
                    nodeTypes={{ cfgNode: CFGNode }}
                    onNodesChange={(changes) => setCfgNodes((nds) => applyNodeChanges(changes, nds))}
                    onEdgesChange={(changes) => setCfgEdges((eds) => applyEdgeChanges(changes, eds))}
                    fitView
                    fitViewOptions={{ padding: 0.2 }}
                    onInit={(rf) => {
                      try {
                        const root = cfgRootId || selected
                        if (root) rf.fitView({ nodes: [{ id: root } as any], padding: 0.2 })
                        else rf.fitView({ padding: 0.2 })
                      } catch {
                        // ignore
                      }
                    }}
                    onNodeClick={(_, node) => {
                      const fid = String(node.id)
                      navigateTo(fid)
                      setCfgRootId(fid)
                      if (jobId) loadCFG(jobId, fid, cfgDepth)
                    }}
                  >
                    <MiniMap nodeColor={() => 'rgba(255,255,255,0.18)'} maskColor='rgba(0,0,0,0.5)' />
                    <Controls />
                    <Background gap={18} size={1} color='rgba(255,255,255,0.08)' />
                  </ReactFlow>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {showExeSummary ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1090,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowExeSummary(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '90vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 12,
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>EXE Summary</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  Built from stored per-function summaries
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button
                  className='smallBtn'
                  onClick={async () => {
                    if (!jobId) return
                    const fd = new FormData()
                    if (providerChoice) fd.set('provider', providerChoice)
                    const effectiveModel =
                      modelChoice || (providerChoice === 'openai' ? openaiDefaultModel : anthropicDefaultModel) || ''
                    if (effectiveModel) fd.set('model', effectiveModel)
                    if (providerChoice === 'openai') {
                      if (openaiBaseUrl.trim()) fd.set('openai_base_url', openaiBaseUrl.trim())
                      if (openaiApiKey.trim()) fd.set('openai_api_key', openaiApiKey.trim())
                      if (openaiApiMode.trim()) fd.set('openai_api_mode', openaiApiMode.trim())
                      if (openaiReasoning.trim()) fd.set('openai_reasoning', openaiReasoning.trim())
                    }
                    await fetch(`${apiBase}/api/jobs/${jobId}/summarize_exe`, { method: 'POST', body: fd })
                    window.setTimeout(() => {
                      loadExeSummary(jobId)
                      loadExeSummaryLogs(jobId)
                    }, 800)
                  }}
                  disabled={!jobId}
                  title='Generate/update EXE summary'
                >
                  Update
                </button>
                <button
                  className='smallBtn'
                  onClick={() => {
                    if (jobId) {
                      loadExeSummary(jobId)
                      loadExeSummaryLogs(jobId)
                    }
                  }}
                  disabled={!jobId}
                >
                  Refresh
                </button>
                <button className='smallBtn' onClick={() => setShowExeSummary(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                  ✕
                </button>
              </div>
            </div>

            <div style={{ padding: 20, overflow: 'auto' }}>
              {!exeSummary || exeSummary?.status === 'not_started' ? (
                <div className='secondary'>No EXE summary yet. Click Update.</div>
              ) : exeSummary?.status === 'error' ? (
                <div style={{ color: 'rgba(255,96,96,0.9)', whiteSpace: 'pre-wrap' }}>
                  {String(exeSummary?.error || 'error')}
                </div>
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
                    <span className='badge'>model: {exeSummary?.model || '-'}</span>
                    {typeof exeSummary?.confidence === 'number' ? <span className='badge'>conf: {exeSummary.confidence.toFixed(2)}</span> : null}
                    {typeof exeSummary?.functions_n === 'number' ? <span className='badge'>functions: {exeSummary.functions_n}</span> : null}
                    {exeSummary?.updated_at ? <span className='badge'>updated: {fmtJst(exeSummary.updated_at)}</span> : null}
                  </div>
                  <div className='codeBlock' style={{ whiteSpace: 'pre-wrap' }}>
                    {String(exeSummary?.summary_ja || '')}
                  </div>
                </>
              )}

              <div style={{ height: 14 }} />
              <details className='fold' open>
                <summary className='foldSummary'>Debug logs ({exeSummaryLogs.length})</summary>
                <div className='foldBody'>
                  <div className='logBox'>
                    {(exeSummaryLogs || []).slice(-200).map((x: any, i: number) => (
                      <div key={i} className='logRow'>
                        <span className='logTs'>{fmtJst(x?.ts) || ''}</span>
                        <span className='logEvt'>{String(x?.event ?? '')}</span>
                        <span className='logMsg'>
                          {x?.task ? `task=${x.task} ` : ''}
                          {x?.model ? `model=${x.model} ` : ''}
                          {x?.status_code ? `status=${x.status_code} ` : ''}
                          {typeof x?.api_ms === 'number' ? `api_ms=${x.api_ms} ` : ''}
                          {typeof x?.functions_n === 'number' ? `functions_n=${x.functions_n} ` : ''}
                          {x?.error ? `error=${x.error}` : ''}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </details>
            </div>
          </div>
        </div>
      ) : null}

      {showStrings ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1090,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowStrings(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '90vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 12,
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Strings</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  extracted from Ghidra defined data ({analysis?.strings?.length ?? 0})
                  {analysis?.strings?.length && analysis.strings.length >= 50000 ? ' (capped at 50k)' : ''}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <input
                  className='input'
                  value={stringQuery}
                  onChange={(e) => setStringQuery(e.target.value)}
                  placeholder='filter...'
                  style={{ padding: '6px 8px', width: 240 }}
                />
                <input
                  className='input'
                  type='number'
                  min={0}
                  value={stringMinLen}
                  onChange={(e) => setStringMinLen(Number(e.target.value || 0))}
                  placeholder='min len'
                  title='min length (0=off)'
                  style={{ padding: '6px 8px', width: 110 }}
                />
                <input
                  className='input'
                  type='number'
                  min={0}
                  value={stringMaxLen}
                  onChange={(e) => setStringMaxLen(Number(e.target.value || 0))}
                  placeholder='max len'
                  title='max length (0=off)'
                  style={{ padding: '6px 8px', width: 110 }}
                />
                <button className='smallBtn' onClick={() => setShowStrings(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                  ✕
                </button>
              </div>
            </div>

            <div style={{ padding: 20, overflow: 'auto' }}>
              {(analysis?.strings ?? [])
                .filter((s) => {
                  const q = stringQuery.trim().toLowerCase()
                  const v = String(s.value ?? '')
                  const a = String(s.addr ?? '')
                  const len = Number(s.len ?? v.length ?? 0)

                  if (q && !v.toLowerCase().includes(q) && !a.toLowerCase().includes(q)) return false

                  const minL = Math.max(0, Number(stringMinLen || 0))
                  const maxL = Math.max(0, Number(stringMaxLen || 0))
                  if (minL > 0 && len < minL) return false
                  if (maxL > 0 && len > maxL) return false

                  return true
                })
                .map((s, i) => (
                  <div
                    key={`str-${i}-${s.addr}`}
                    className='fnItem'
                    style={{
                      padding: '10px 12px',
                      display: 'block', // override .fnItem grid layout (which pushes the 2nd child to the right column)
                      cursor: 'default',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                      <div style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.9)' }}>{s.addr}</div>
                      <div className='secondary' style={{ fontSize: 12 }}>
                        {s.len != null ? `${s.len} chars` : ''} {s.type ? `• ${s.type}` : ''}
                      </div>
                    </div>
                    <div
                      style={{
                        marginTop: 6,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        textAlign: 'left',
                        width: '100%',
                      }}
                    >
                      {s.value}
                    </div>
                  </div>
                ))}
              {!analysis?.strings?.length ? <div className='secondary'>No strings. Re-extract needed.</div> : null}
            </div>
          </div>
        </div>
      ) : null}

      {showXrefs && selectedFn ? (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            zIndex: 1100,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20,
          }}
          onClick={() => setShowXrefs(false)}
        >
          <div
            style={{
              background: '#1a1a1a',
              borderRadius: 12,
              maxWidth: '90vw',
              width: '100%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              border: '1px solid rgba(255,255,255,0.1)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 18 }}>Xrefs</h3>
                <div className='secondary' style={{ fontSize: 12, marginTop: 4 }}>
                  {displayName(selectedFn.id)} ({selectedFn.id})
                </div>
              </div>
              <button className='smallBtn' onClick={() => setShowXrefs(false)} style={{ fontSize: 20, padding: '4px 12px' }}>
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, padding: 20, overflow: 'auto' }}>
              <div>
                <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                  <strong>Called by</strong>
                  <span className='badge'>{(selectedFn.called_by ?? []).length}</span>
                </div>
                <div className='functionList'>
                  {(selectedFn.called_by ?? []).length ? (
                    (selectedFn.called_by ?? []).map((fid) => {
                      const label = displayName(fid)
                      return (
                        <div
                          key={`in-${fid}`}
                          className='fnItem'
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            navigateTo(fid)
                            setShowXrefs(false)
                          }}
                          title={fid}
                        >
                          <div className='fnMeta'>
                            <div className='fnName'>← {label}</div>
                            <div className='fnSub'>
                              <span style={{ fontFamily: 'monospace' }}>{fid}</span>
                            </div>
                          </div>
                        </div>
                      )
                    })
                  ) : (
                    <div className='secondary'>No callers found.</div>
                  )}
                </div>
              </div>

              <div>
                <div className='sectionTitleRow' style={{ marginBottom: 8 }}>
                  <strong>Calls out</strong>
                  <span className='badge'>{(selectedFn.calls_out ?? []).length}</span>
                </div>
                <div className='functionList'>
                  {(selectedFn.calls_out ?? []).length ? (
                    (selectedFn.calls_out ?? []).map((fid, i) => {
                      const label = displayName(fid)
                      return (
                        <div
                          key={`out-${fid}-${i}`}
                          className='fnItem'
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            navigateTo(fid, { from: selectedFn.id, recordEdge: true })
                            setShowXrefs(false)
                          }}
                          title={fid}
                        >
                          <div className='fnMeta'>
                            <div className='fnName'>→ {label}</div>
                            <div className='fnSub'>
                              <span style={{ fontFamily: 'monospace' }}>{fid}</span>
                            </div>
                          </div>
                        </div>
                      )
                    })
                  ) : (
                    <div className='secondary'>No outgoing calls found.</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {/* Chat Assistant Button */}
      {!showChat && jobId && (
        <button
          className='chatFloatingBtn'
          onClick={() => setShowChat(true)}
          title='Open AI Assistant'
        >
          💬
        </button>
      )}

      {/* Floating Chat Window */}
      {showChat && jobId && (
        <div
          className='chatWindow'
          style={{
            position: 'fixed',
            left: chatPosition.x,
            top: chatPosition.y,
            width: chatMinimized ? 300 : 450,
            height: chatMinimized ? 50 : 600,
            zIndex: 2000,
            display: 'flex',
            flexDirection: 'column',
            background: '#1a1a1a',
            border: '1px solid rgba(255,255,255,0.2)',
            borderRadius: 12,
            boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }}
        >
          {/* Title Bar (Draggable) */}
          <div
            className='chatTitleBar'
            style={{
              padding: '12px 16px',
              borderBottom: chatMinimized ? 'none' : '1px solid rgba(255,255,255,0.1)',
              cursor: 'move',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              userSelect: 'none',
            }}
            onMouseDown={(e) => {
              const startX = e.clientX - chatPosition.x
              const startY = e.clientY - chatPosition.y
              const onMove = (me: MouseEvent) => {
                setChatPosition({ x: me.clientX - startX, y: me.clientY - startY })
              }
              const onUp = () => {
                document.removeEventListener('mousemove', onMove)
                document.removeEventListener('mouseup', onUp)
              }
              document.addEventListener('mousemove', onMove)
              document.addEventListener('mouseup', onUp)
            }}
          >
            <div style={{ fontWeight: 600 }}>🤖 AI Assistant</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className='chatBtn'
                onClick={() => setChatMinimized(!chatMinimized)}
                title={chatMinimized ? 'Restore' : 'Minimize'}
              >
                {chatMinimized ? '⬜' : '➖'}
              </button>
              <button
                className='chatBtn'
                onClick={() => setShowChat(false)}
                title='Close'
              >
                ✕
              </button>
            </div>
          </div>

          {/* Chat Body */}
          {!chatMinimized && (
            <>
              <div
                className='chatMessages'
                style={{
                  flex: 1,
                  overflowY: 'auto',
                  padding: 16,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                }}
              >
                <div
                  style={{
                    position: 'sticky',
                    top: 0,
                    zIndex: 1,
                    background: '#1a1a1a',
                    paddingBottom: 10,
                    marginBottom: 4,
                    borderBottom: '1px solid rgba(255,255,255,0.08)',
                  }}
                >
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select
                      className='input'
                      style={{ width: 130, padding: '6px 8px', borderRadius: 10 }}
                      value={chatProvider}
                      onChange={(e) => setChatProvider(e.target.value as any)}
                      disabled={chatLoading}
                    >
                      <option value='openai'>OpenAI-compatible</option>
                      <option value='anthropic'>Anthropic</option>
                    </select>
                    <input
                      className='input'
                      style={{ flex: 1, padding: '6px 8px', borderRadius: 10 }}
                      placeholder='model (optional)'
                      value={chatModel}
                      onChange={(e) => setChatModel(e.target.value)}
                      disabled={chatLoading}
                    />
                    <button
                      className='smallBtn'
                      onClick={() => setShowChatDebug(!showChatDebug)}
                      disabled={chatLoading}
                      style={{ padding: '6px 10px', borderRadius: 10, opacity: showChatDebug ? 1 : 0.5 }}
                      title='Toggle debug info'
                    >
                      🔧
                    </button>
                    <button
                      className='smallBtn'
                      onClick={() => {
                        if (confirm('Clear chat history?')) {
                          setChatMessages([])
                          setChatError(null)
                        }
                      }}
                      disabled={chatLoading}
                      style={{ padding: '6px 10px', borderRadius: 10 }}
                      title='Clear chat history'
                    >
                      🗑️
                    </button>
                  </div>
                  {chatError ? (
                    <div style={{ marginTop: 8, color: 'rgba(255,96,96,0.9)', fontSize: 12, whiteSpace: 'pre-wrap' }}>
                      {chatError}
                    </div>
                  ) : null}
                </div>
                {chatMessages.length === 0 && (
                  <div className='secondary' style={{ textAlign: 'center', marginTop: 40 }}>
                    <div style={{ fontSize: 24, marginBottom: 8 }}>👋</div>
                    <div>Ask me anything about this binary!</div>
                    <div style={{ fontSize: 12, marginTop: 8 }}>
                      I can navigate functions, search strings, analyze code, and more.
                    </div>
                  </div>
                )}
                {chatMessages.map((msg, i) => (
                  <div
                    key={i}
                    style={{
                      alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                      maxWidth: '80%',
                      background: msg.role === 'user' ? 'rgba(77, 163, 255, 0.2)' : 'rgba(255,255,255,0.08)',
                      border: `1px solid ${msg.role === 'user' ? 'rgba(77, 163, 255, 0.3)' : 'rgba(255,255,255,0.12)'}`,
                      borderRadius: 10,
                      padding: '10px 14px',
                      wordBreak: 'break-word',
                      overflowWrap: 'break-word',
                    }}
                  >
                    {msg.debug?.thought && showChatDebug && (
                      <div style={{ marginBottom: 8, padding: '6px 8px', background: 'rgba(255,215,0,0.1)', borderRadius: 6, fontSize: 11, borderLeft: '3px solid rgba(255,215,0,0.5)' }}>
                        <div className='secondary' style={{ fontWeight: 600, marginBottom: 4 }}>
                          💭 Thinking
                          {msg.debug.step_count && msg.debug.max_steps && (
                            <span style={{ marginLeft: 8, fontSize: 10, opacity: 0.7 }}>
                              (Step {msg.debug.step_count}/{msg.debug.max_steps})
                            </span>
                          )}
                        </div>
                        <div className='secondary' style={{ fontSize: 11, lineHeight: 1.4 }}>{msg.debug.thought}</div>
                        {msg.debug.active_function_id && (
                          <div className='secondary' style={{ fontSize: 10, marginTop: 4, opacity: 0.7 }}>
                            📍 Active: {msg.debug.active_function_id}
                          </div>
                        )}
                      </div>
                    )}
                    <div style={{ fontSize: 13, lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{msg.content}</div>
                    {showChatDebug && msg.debug && msg.debug.tool_count > 0 && (
                      <div style={{ marginTop: 8, padding: '6px 8px', background: 'rgba(255,255,255,0.05)', borderRadius: 6, fontSize: 11, wordBreak: 'break-all' }}>
                        <div className='secondary' style={{ fontWeight: 600, marginBottom: 4 }}>🔧 Tools used ({msg.debug.tool_count}):</div>
                        {msg.debug.tool_calls_requested.map((tc: any, idx: number) => (
                          <div key={idx} className='secondary' style={{ fontFamily: 'monospace', fontSize: 10, wordBreak: 'break-all' }}>
                            • {tc.tool}({JSON.stringify(tc.args).slice(0, 60)}{JSON.stringify(tc.args).length > 60 ? '...' : ''})
                          </div>
                        ))}
                      </div>
                    )}
                    <div className='secondary' style={{ fontSize: 10, marginTop: 6 }}>
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
                <div ref={chatMessagesEndRef} />
                {chatLoading && (
                  <div style={{ alignSelf: 'flex-start', color: 'rgba(255,255,255,0.6)', fontSize: 13 }}>
                    Thinking...
                  </div>
                )}
              </div>

              {/* Input */}
              <div style={{ padding: 12, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    type='text'
                    className='input'
                    placeholder='Ask something...'
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey && chatInput.trim()) {
                        e.preventDefault()
                        const msg = chatInput.trim()
                        const now = new Date().toISOString()
                        setChatInput('')
                        setChatError(null)
                        setChatMessages((prev) => [...prev, { role: 'user', content: msg, timestamp: now }])
                        setChatLoading(true)

                        ;(async () => {
                          try {
                            const history = chatMessages
                              .slice(-20)
                              .map((m) => ({ role: m.role, content: m.content }))
                            const body: any = {
                              job_id: jobId,
                              provider: chatProvider,
                              message: msg,
                              history,
                            }
                            if (chatModel.trim()) body.model = chatModel.trim()
                            if (openaiBaseUrl.trim()) body.base_url = openaiBaseUrl.trim()
                            if (openaiApiKey.trim()) body.api_key = openaiApiKey.trim()

                            const r = await fetch(`${apiBase}/api/chat`, {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify(body),
                            })
                            const data = await r.json().catch(() => null)
                            if (!r.ok) {
                              throw new Error((data && (data.detail || data.error)) || `HTTP ${r.status}`)
                            }

                            const reply = String(data?.reply ?? '')
                            const ts = new Date().toISOString()
                            const debug = data?.debug || null
                            setChatMessages((prev) => [...prev, { role: 'assistant', content: reply || '(no response)', timestamp: ts, debug }])

                            // Apply UI actions (e.g., navigate)
                            const actions = Array.isArray(data?.ui_actions) ? data.ui_actions : []
                            for (const a of actions) {
                              if (a?.action === 'navigate' && a?.function_id) {
                                navigateTo(String(a.function_id), { from: selected ?? undefined, recordEdge: true })
                              }
                            }
                          } catch (err: any) {
                            setChatError(String(err?.message || err))
                          } finally {
                            setChatLoading(false)
                          }
                        })()
                      }
                    }}
                    disabled={chatLoading}
                  />
                  <button
                    className='smallBtn'
                    onClick={() => {
                      const msg = chatInput.trim()
                      if (!msg) return
                      const now = new Date().toISOString()
                      setChatInput('')
                      setChatError(null)
                      setChatMessages((prev) => [...prev, { role: 'user', content: msg, timestamp: now }])
                      setChatLoading(true)

                      ;(async () => {
                        try {
                          const history = chatMessages
                            .slice(-20)
                            .map((m) => ({ role: m.role, content: m.content }))
                          const body: any = {
                            job_id: jobId,
                            provider: chatProvider,
                            message: msg,
                            history,
                          }
                          if (chatModel.trim()) body.model = chatModel.trim()
                          if (openaiBaseUrl.trim()) body.base_url = openaiBaseUrl.trim()
                          if (openaiApiKey.trim()) body.api_key = openaiApiKey.trim()

                          const r = await fetch(`${apiBase}/api/chat`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(body),
                          })
                          const data = await r.json().catch(() => null)
                          if (!r.ok) {
                            throw new Error((data && (data.detail || data.error)) || `HTTP ${r.status}`)
                          }

                          const reply = String(data?.reply ?? '')
                          const ts = new Date().toISOString()
                          const debug = data?.debug || null
                          setChatMessages((prev) => [...prev, { role: 'assistant', content: reply || '(no response)', timestamp: ts, debug }])

                          const actions = Array.isArray(data?.ui_actions) ? data.ui_actions : []
                          for (const a of actions) {
                            if (a?.action === 'navigate' && a?.function_id) {
                              navigateTo(String(a.function_id), { from: selected ?? undefined, recordEdge: true })
                            }
                          }
                        } catch (err: any) {
                          setChatError(String(err?.message || err))
                        } finally {
                          setChatLoading(false)
                        }
                      })()
                    }}
                    disabled={chatLoading || !chatInput.trim()}
                  >
                    Send
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
