// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MarkdownText } from './MarkdownText'

describe('MarkdownText Component', () => {
  it('renders null when content is empty or undefined', () => {
    const { container } = render(<MarkdownText text="" />)
    expect(container.firstChild).toBeNull()

    const { container: containerNull } = render(<MarkdownText text={null} />)
    expect(containerNull.firstChild).toBeNull()
  })

  it('renders standard markdown elements (headings, bold, italics, paragraphs)', () => {
    const markdown = `# Main Title
## Subtitle
This is **bold** text and *italic* text.`

    render(<MarkdownText text={markdown} />)

    const h1 = screen.getByRole('heading', { level: 1 })
    expect(h1.textContent).toBe('Main Title')

    const h2 = screen.getByRole('heading', { level: 2 })
    expect(h2.textContent).toBe('Subtitle')

    expect(screen.getByText('bold')).not.toBeNull()
    expect(screen.getByText('italic')).not.toBeNull()
  })

  it('renders unordered and ordered lists', () => {
    const markdown = `
- Item Alpha
- Item Beta

1. Step One
2. Step Two
`
    render(<MarkdownText text={markdown} />)

    expect(screen.getByText('Item Alpha')).not.toBeNull()
    expect(screen.getByText('Item Beta')).not.toBeNull()
    expect(screen.getByText('Step One')).not.toBeNull()
    expect(screen.getByText('Step Two')).not.toBeNull()
  })

  it('renders fenced code blocks with language badge and copy action', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    })

    const markdown = '```bash\nnmap -sV 192.168.1.1\n```'
    render(<MarkdownText text={markdown} />)

    expect(screen.getByText('bash')).not.toBeNull()
    expect(screen.getByText('nmap -sV 192.168.1.1')).not.toBeNull()

    const copyBtn = screen.getByRole('button', { name: /copy code snippet/i })
    expect(copyBtn).not.toBeNull()

    fireEvent.click(copyBtn)
    expect(writeTextMock).toHaveBeenCalledWith('nmap -sV 192.168.1.1')
  })

  it('renders inline code with custom mono styling', () => {
    const markdown = 'Use `curl -I https://target.local` to inspect headers.'
    render(<MarkdownText text={markdown} />)

    const inlineCode = screen.getByText('curl -I https://target.local')
    expect(inlineCode.tagName.toLowerCase()).toBe('code')
  })

  it('renders links with secure attributes (target="_blank" and rel="noopener noreferrer")', () => {
    const markdown = 'Read the [OWASP Guide](https://owasp.org) for details.'
    render(<MarkdownText text={markdown} />)

    const link = screen.getByRole('link', { name: 'OWASP Guide' })
    expect(link.getAttribute('href')).toBe('https://owasp.org')
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
  })

  it('renders GFM tables with columns and cells', () => {
    const markdown = `
| Port | Service | State |
| --- | --- | --- |
| 80 | HTTP | open |
| 443 | HTTPS | open |
`
    render(<MarkdownText text={markdown} />)

    expect(screen.getByText('Port')).not.toBeNull()
    expect(screen.getByText('Service')).not.toBeNull()
    expect(screen.getByText('HTTP')).not.toBeNull()
    expect(screen.getByText('HTTPS')).not.toBeNull()
  })

  it('renders in inline mode with a span root without wrapping block p tags', () => {
    const { container } = render(
      <MarkdownText text="Impact: **Critical** vulnerability detected" inline />
    )

    const rootSpan = container.querySelector('span.markdown-content')
    expect(rootSpan).not.toBeNull()
    expect(container.querySelector('p')).toBeNull()
    expect(screen.getByText('Critical')).not.toBeNull()
  })
})
