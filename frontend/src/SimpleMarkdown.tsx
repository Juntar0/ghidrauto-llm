import React from 'react'

interface MarkdownProps {
  text: string
}

export function SimpleMarkdown({ text }: MarkdownProps) {
  // Split by double newline for paragraphs
  const blocks = text.split(/\n\n+/).filter(b => b.trim())

  return (
    <div>
      {blocks.map((block, idx) => {
        block = block.trim()

        // Headers
        if (block.startsWith('## ')) {
          return (
            <h2 key={idx} style={{ margin: '0.7em 0 0.3em', fontSize: '1.2em' }}>
              {renderInline(block.substring(3))}
            </h2>
          )
        }
        if (block.startsWith('# ')) {
          return (
            <h1 key={idx} style={{ margin: '0.8em 0 0.4em', fontSize: '1.4em' }}>
              {renderInline(block.substring(2))}
            </h1>
          )
        }

        // Lists
        if (block.startsWith('- ')) {
          const items = block.split('\n').filter(line => line.startsWith('- '))
          return (
            <ul key={idx} style={{ margin: '0.5em 0', paddingLeft: '1.5em' }}>
              {items.map((item, i) => (
                <li key={i} style={{ margin: '0.3em 0' }}>
                  {renderInline(item.substring(2))}
                </li>
              ))}
            </ul>
          )
        }

        // Code block (triple backtick)
        if (block.startsWith('```')) {
          const code = block.replace(/```/g, '').trim()
          return (
            <pre key={idx} style={{ background: 'rgba(0,0,0,0.3)', padding: '10px', borderRadius: 6, overflowX: 'auto', margin: '0.5em 0' }}>
              <code style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{code}</code>
            </pre>
          )
        }

        // Blockquote
        if (block.startsWith('> ')) {
          const quote = block.split('\n').map(line => line.replace(/^> /, '')).join('\n')
          return (
            <blockquote key={idx} style={{ borderLeft: '3px solid rgba(255,255,255,0.3)', paddingLeft: '10px', margin: '0.5em 0', opacity: 0.85 }}>
              {renderInline(quote)}
            </blockquote>
          )
        }

        // Regular paragraph
        return (
          <p key={idx} style={{ margin: '0.5em 0' }}>
            {renderInline(block)}
          </p>
        )
      })}
    </div>
  )
}

// Render inline elements (bold, code, links)
function renderInline(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = []
  let current = 0

  // Patterns: **bold**, `code`, [link](url)
  const regex = /\*\*(.+?)\*\*|`(.+?)`|\[(.+?)\]\((.+?)\)/g
  let match

  while ((match = regex.exec(text)) !== null) {
    // Add text before match
    if (match.index > current) {
      parts.push(text.substring(current, match.index))
    }

    if (match[1]) {
      // Bold
      parts.push(
        <strong key={parts.length} style={{ fontWeight: 600 }}>
          {match[1]}
        </strong>
      )
    } else if (match[2]) {
      // Inline code
      parts.push(
        <code
          key={parts.length}
          style={{
            background: 'rgba(255,255,255,0.1)',
            padding: '2px 6px',
            borderRadius: 4,
            fontFamily: 'monospace',
            fontSize: '0.9em',
            whiteSpace: 'nowrap',
            display: 'inline',
          }}
        >
          {match[2]}
        </code>
      )
    } else if (match[3] && match[4]) {
      // Link
      parts.push(
        <a key={parts.length} href={match[4]} style={{ color: '#60a5fa', textDecoration: 'underline' }} target="_blank" rel="noreferrer">
          {match[3]}
        </a>
      )
    }

    current = regex.lastIndex
  }

  // Add remaining text
  if (current < text.length) {
    parts.push(text.substring(current))
  }

  return parts.length ? parts : [text]
}
