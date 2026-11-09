import {
  useState,
  useRef,
  isValidElement,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Check, Copy } from 'lucide-react'

export interface MarkdownTextProps {
  text?: string | null
  children?: string | null
  className?: string
  inline?: boolean
}

function PreBlock({
  children,
  ...props
}: ComponentPropsWithoutRef<'pre'>) {
  const [copied, setCopied] = useState(false)
  const preRef = useRef<HTMLPreElement>(null)

  let language = ''
  let rawCode = ''

  if (isValidElement(children)) {
    const childProps = children.props as {
      className?: string
      children?: ReactNode
    }
    const match = /language-(\w+)/.exec(childProps?.className || '')
    if (match) {
      language = match[1]
    }
    if (typeof childProps?.children === 'string') {
      rawCode = childProps.children
    } else if (Array.isArray(childProps?.children)) {
      rawCode = childProps.children.map((c) => (typeof c === 'string' ? c : '')).join('')
    }
  }

  const handleCopy = () => {
    const textToCopy = (preRef.current?.textContent || rawCode || '').replace(/\n$/, '')
    if (!textToCopy) return
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 1600)
        }).catch(() => {})
      }
    } catch {
      // Ignore clipboard write failures in unsupported test environments
    }
  }

  return (
    <div className="markdown-pre-wrap">
      <div className="markdown-pre-header">
        <span className="markdown-pre-lang mono">{language || 'code'}</span>
        <button
          type="button"
          className="markdown-copy-btn"
          onClick={handleCopy}
          aria-label={copied ? 'Copied to clipboard' : 'Copy code snippet'}
          title={copied ? 'Copied!' : 'Copy code'}
        >
          {copied ? (
            <>
              <Check size={12} strokeWidth={2} aria-hidden="true" />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Copy size={12} strokeWidth={2} aria-hidden="true" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre ref={preRef} className="markdown-pre mono" {...props}>
        {children}
      </pre>
    </div>
  )
}

function LinkBlock({
  href,
  children,
  ...props
}: ComponentPropsWithoutRef<'a'>) {
  const isExternal = href?.startsWith('http://') || href?.startsWith('https://')
  return (
    <a
      href={href}
      target={isExternal ? '_blank' : undefined}
      rel={isExternal ? 'noopener noreferrer' : undefined}
      className="markdown-link"
      {...props}
    >
      {children}
    </a>
  )
}

function TableBlock({
  children,
  ...props
}: ComponentPropsWithoutRef<'table'>) {
  return (
    <div className="markdown-table-wrap">
      <table className="markdown-table" {...props}>
        {children}
      </table>
    </div>
  )
}

export function MarkdownText({
  text,
  children,
  className = '',
  inline = false,
}: MarkdownTextProps) {
  const content = text ?? children
  if (content === undefined || content === null || content === '') {
    return null
  }

  const containerClass = `markdown-content ${className}`.trim()

  if (inline) {
    return (
      <span className={containerClass}>
        <Markdown
          remarkPlugins={[remarkGfm]}
          components={{
            p: ({ children: pChildren }) => <span>{pChildren}</span>,
            a: LinkBlock,
          }}
        >
          {content}
        </Markdown>
      </span>
    )
  }

  return (
    <div className={containerClass}>
      <Markdown
        remarkPlugins={[remarkGfm]}
        components={{
          pre: PreBlock,
          a: LinkBlock,
          table: TableBlock,
        }}
      >
        {content}
      </Markdown>
    </div>
  )
}
