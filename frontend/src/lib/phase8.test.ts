// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest'
import { readTheme, applyTheme, resolvedTheme } from './theme'
import { briefText } from './mission'
import type { AssessmentDetail } from './schemas'

describe('Phase 8 Theme and UI Tests', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  it('defaults to system theme when localStorage is empty', () => {
    expect(readTheme()).toBe('system')
  })

  it('reads stored dark or light theme from localStorage', () => {
    localStorage.setItem('aipent-theme', 'dark')
    expect(readTheme()).toBe('dark')

    localStorage.setItem('aipent-theme', 'light')
    expect(readTheme()).toBe('light')

    localStorage.setItem('aipent-theme', 'invalid')
    expect(readTheme()).toBe('system')
  })

  it('applies dark theme by setting data-theme attribute and persisting', () => {
    applyTheme('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(localStorage.getItem('aipent-theme')).toBe('dark')
  })

  it('applies light theme by setting data-theme attribute and persisting', () => {
    applyTheme('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(localStorage.getItem('aipent-theme')).toBe('light')
  })

  it('applies system theme by removing data-theme attribute', () => {
    document.documentElement.dataset.theme = 'dark'
    applyTheme('system')
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
    expect(localStorage.getItem('aipent-theme')).toBe('system')
  })

  it('resolves theme from system preference media query', () => {
    window.matchMedia = ((query: string) => ({
      matches: query.includes('dark'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia

    expect(resolvedTheme('system')).toBe('dark')
    expect(resolvedTheme('light')).toBe('light')
    expect(resolvedTheme('dark')).toBe('dark')
  })

  it('formats briefText with §12.10 exact wording', () => {
    const dummyDetail: AssessmentDetail = {
      id: 1,
      title: 'Lab Test',
      targets: ['192.168.1.10'],
      ports: [80, 443],
      exclusions: [],
      status: 'active',
      risk_score: null,
      created_at: new Date().toISOString(),
      finished_at: null,
      request: 'Security assessment objective',
      report_path: null,
      report_sha256: null,
      steps: [],
      findings: [],
      evidence: [],
      approvals: [],
      audit: [],
      messages: [],
      reasoning: {
        hypotheses: [],
        decisions: [],
        open_questions: [],
        coverage: {},
      },
      gate_open: false,
      active_role: null,
    }

    const text = briefText(dummyDetail)
    expect(text).toContain(
      'Every consequential action stops here for approval before it runs.',
    )
  })

  it('verifies WCAG AA contrast ratio (> 4.5:1) for all core theme tokens', () => {
    function srgbToLin(c: number): number {
      const v = c / 255.0
      return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)
    }

    function luminance(hex: string): number {
      const clean = hex.replace('#', '')
      const r = parseInt(clean.substring(0, 2), 16)
      const g = parseInt(clean.substring(2, 4), 16)
      const b = parseInt(clean.substring(4, 6), 16)
      return (
        0.2126 * srgbToLin(r) + 0.7152 * srgbToLin(g) + 0.0722 * srgbToLin(b)
      )
    }

    function contrast(hex1: string, hex2: string): number {
      const l1 = luminance(hex1)
      const l2 = luminance(hex2)
      const lighter = Math.max(l1, l2)
      const darker = Math.min(l1, l2)
      return (lighter + 0.05) / (darker + 0.05)
    }

    const lightTheme = {
      paper: '#f1ece2',
      paper_raised: '#f8f4eb',
      ink: '#1b1915',
      ink_soft: '#4b453b',
      ink_muted: '#6f6757',
      oxide: '#9c3527',
      oxide_deep: '#76251a',
      moss: '#3f5b45',
      amber: '#7c5717',
    }

    const darkTheme = {
      paper: '#151411',
      paper_raised: '#1d1b16',
      ink: '#ece5d8',
      ink_soft: '#c9c0b1',
      ink_muted: '#9b9282',
      oxide: '#d4695a',
      oxide_deep: '#e88374',
      moss: '#8fae91',
      amber: '#d6a75c',
    }

    // Light theme body text contrast against paper and paper-raised
    for (const [key, color] of Object.entries(lightTheme)) {
      if (key.startsWith('paper')) continue
      const crPaper = contrast(color, lightTheme.paper)
      const crRaised = contrast(color, lightTheme.paper_raised)
      expect(crPaper).toBeGreaterThanOrEqual(4.5)
      expect(crRaised).toBeGreaterThanOrEqual(4.5)
    }

    // Dark theme body text contrast against paper and paper-raised
    for (const [key, color] of Object.entries(darkTheme)) {
      if (key.startsWith('paper')) continue
      const crPaper = contrast(color, darkTheme.paper)
      const crRaised = contrast(color, darkTheme.paper_raised)
      expect(crPaper).toBeGreaterThanOrEqual(4.5)
      expect(crRaised).toBeGreaterThanOrEqual(4.5)
    }
  })
})
