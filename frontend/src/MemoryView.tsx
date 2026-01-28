import { useEffect, useMemo, useRef, useState } from 'react'

type MemoryResp = {
  job_id: string
  va: string
  len: number
  bytes_b64: string
  arch?: 'x86' | 'x64' | null
  ptr_size?: number | null
  annotations?: {
    image_base?: string
    image_size?: number
    section?: string
    perm?: string
    label?: string
  }
  error?: string | null
}

function parseHexVa(s: string): number | null {
  const t = (s || '').trim().toLowerCase().replace(/_/g, '')
  const x = t.startsWith('0x') ? t.slice(2) : t
  if (!x || !/^[0-9a-f]+$/.test(x)) return null
  // JS number is safe up to 2^53; VA fits.
  return parseInt(x, 16)
}

function fmtVa(n: number) {
  return '0x' + n.toString(16)
}

function b64ToU8(b64: string): Uint8Array {
  const bin = atob(b64)
  const u8 = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}

function isPrintable(b: number) {
  return b >= 0x20 && b <= 0x7e
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ')
}

function bytesToAscii(bytes: Uint8Array) {
  return Array.from(bytes)
    .map((b) => (isPrintable(b) ? String.fromCharCode(b) : '.'))
    .join('')
}

export default function MemoryView(props: {
  apiBase: string
  jobId: string
  initialAddr?: string
  onClose: () => void
}) {
  const { apiBase, jobId, initialAddr, onClose } = props

  const [addr, setAddr] = useState(initialAddr || '')
  const [length, setLength] = useState(0x200)
  const [loading, setLoading] = useState(false)
  const [resp, setResp] = useState<MemoryResp | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const [anchor, setAnchor] = useState<number | null>(null)
  const [sel, setSel] = useState<{ a: number; b: number } | null>(null)
  const dragging = useRef(false)

  const bytes = useMemo(() => {
    if (!resp?.bytes_b64) return null
    try {
      return b64ToU8(resp.bytes_b64)
    } catch {
      return null
    }
  }, [resp?.bytes_b64])

  const baseVa = useMemo(() => {
    const v = resp?.va || addr
    const n = parseHexVa(v)
    return n
  }, [resp?.va, addr])

  const ptrSize = useMemo(() => {
    const ps = resp?.ptr_size
    if (ps === 4 || ps === 8) return ps
    // fallback
    return resp?.arch === 'x86' ? 4 : 8
  }, [resp?.ptr_size, resp?.arch])

  async function view() {
    const n = parseHexVa(addr)
    if (n == null) {
      setErr('addr must be hex VA (e.g. 0x140003000)')
      return
    }

    setErr(null)
    setLoading(true)
    try {
      const url = `${apiBase}/api/jobs/${jobId}/memory/view?addr=${encodeURIComponent(fmtVa(n))}&len=${length}`
      const r = await fetch(url)
      const j = (await r.json()) as MemoryResp
      setResp(j)
      setSel(null)
      setAnchor(null)
    } catch (e: any) {
      setErr(String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (initialAddr) {
      setAddr(initialAddr)
      // don't auto-fire if empty
      setTimeout(() => view(), 0)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const rows = useMemo(() => {
    if (!bytes || baseVa == null) return []
    const out: Array<{ row: number; addr: number; chunk: Uint8Array }> = []
    for (let i = 0; i < bytes.length; i += 16) {
      out.push({ row: i / 16, addr: baseVa + i, chunk: bytes.slice(i, i + 16) })
    }
    return out
  }, [bytes, baseVa])

  function normalizedSel() {
    if (!sel) return null
    const lo = Math.min(sel.a, sel.b)
    const hi = Math.max(sel.a, sel.b)
    return { lo, hi }
  }

  const selNorm = normalizedSel()

  function setSelectionToOffset(off: number) {
    if (anchor == null) {
      setAnchor(off)
      setSel({ a: off, b: off + 1 })
      return
    }
    setSel({ a: anchor, b: off + 1 })
  }

  function onMouseDownByte(off: number) {
    dragging.current = true
    setAnchor(off)
    setSel({ a: off, b: off + 1 })
  }

  function onMouseEnterByte(off: number) {
    if (!dragging.current) return
    setSelectionToOffset(off)
  }

  function onMouseUp() {
    dragging.current = false
  }

  async function copyText(t: string) {
    try {
      await navigator.clipboard.writeText(t)
    } catch {
      // ignore
    }
  }

  function selectionBytes(): Uint8Array | null {
    if (!bytes || !selNorm) return null
    return bytes.slice(selNorm.lo, selNorm.hi)
  }

  function selectedVa(): number | null {
    if (baseVa == null || !selNorm) return null
    return baseVa + selNorm.lo
  }

  function followPointer() {
    const sb = selectionBytes()
    if (!sb || sb.length < ptrSize) return
    let val = 0n
    for (let i = 0; i < ptrSize; i++) {
      val |= BigInt(sb[i]) << (BigInt(8) * BigInt(i))
    }
    const next = Number(val)
    if (!Number.isFinite(next)) return
    setAddr(fmtVa(next))
    setTimeout(() => view(), 0)
  }

  const viewAsText = useMemo(() => {
    const sb = selectionBytes()
    if (!sb) return null
    return {
      ascii: bytesToAscii(sb),
      hex: bytesToHex(sb),
    }
  }, [selNorm, bytes])

  return (
    <div className='memModal' onMouseUp={onMouseUp}>
      <div className='memModalInner'>
        <div className='memHeader'>
          <div className='memTitle'>Memory View</div>
          <div className='memTools'>
            <span className='memMeta'>job: {jobId.slice(0, 8)}…</span>
            <button className='btn' onClick={onClose}>Close</button>
          </div>
        </div>

        <div className='memBar'>
          <label>Go to:</label>
          <input value={addr} onChange={(e) => setAddr(e.target.value)} placeholder='0x140003000' />
          <label>Len:</label>
          <select value={length} onChange={(e) => setLength(parseInt(e.target.value, 10))}>
            {[0x100, 0x200, 0x400, 0x800, 0x1000].map((v) => (
              <option key={v} value={v}>
                0x{v.toString(16)}
              </option>
            ))}
          </select>
          <button className='btn primary' disabled={loading} onClick={view}>
            {loading ? 'Loading…' : 'View'}
          </button>
          {resp?.annotations?.section && <span className='memMeta'>[{resp.annotations.section}]</span>}
          {resp?.annotations?.label && <span className='memMeta'>{resp.annotations.label}</span>}
          {resp?.arch && <span className='memMeta'>{resp.arch} (ptr {ptrSize})</span>}
        </div>

        {err && <div className='memError'>{err}</div>}
        {resp?.error && <div className='memError'>backend: {resp.error}</div>}

        <div className='memActions'>
          <button className='btn' disabled={!selNorm} onClick={() => copyText(fmtVa(selectedVa() || 0))}>
            Copy address
          </button>
          <button className='btn' disabled={!selNorm || !bytes} onClick={() => copyText(viewAsText?.hex || '')}>
            Copy bytes
          </button>
          <button className='btn' disabled={!selNorm || !bytes} onClick={() => copyText(viewAsText?.ascii || '')}>
            Copy ASCII
          </button>
          <button className='btn' disabled={!selNorm || !bytes} onClick={followPointer}>
            Follow pointer ({ptrSize})
          </button>
          {selNorm && viewAsText && (
            <span className='memMeta'>sel: {selNorm.hi - selNorm.lo} bytes</span>
          )}
        </div>

        <div className='memBody'>
          <div className='memTable'>
            {rows.map((r) => (
              <div key={r.row} className='memRow'>
                <div className='memAddr'>{fmtVa(r.addr).padEnd(18, ' ')}</div>
                <div className='memHex'>
                  {Array.from(r.chunk).map((b, i) => {
                    const off = r.row * 16 + i
                    const active = selNorm ? off >= selNorm.lo && off < selNorm.hi : false
                    return (
                      <span
                        key={i}
                        className={'memByte ' + (active ? 'memByteSel' : '')}
                        onMouseDown={() => onMouseDownByte(off)}
                        onMouseEnter={() => onMouseEnterByte(off)}
                      >
                        {b.toString(16).padStart(2, '0')}
                      </span>
                    )
                  })}
                </div>
                <div className='memAscii'>
                  {Array.from(r.chunk).map((b, i) => {
                    const off = r.row * 16 + i
                    const active = selNorm ? off >= selNorm.lo && off < selNorm.hi : false
                    return (
                      <span
                        key={i}
                        className={'memChar ' + (active ? 'memByteSel' : '')}
                        onMouseDown={() => onMouseDownByte(off)}
                        onMouseEnter={() => onMouseEnterByte(off)}
                      >
                        {isPrintable(b) ? String.fromCharCode(b) : '.'}
                      </span>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {selNorm && viewAsText && (
          <div className='memFooter'>
            <div className='memFooterCol'>
              <div className='memFooterLabel'>Hex</div>
              <div className='memFooterVal'>{viewAsText.hex}</div>
            </div>
            <div className='memFooterCol'>
              <div className='memFooterLabel'>ASCII</div>
              <div className='memFooterVal'>{viewAsText.ascii}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
