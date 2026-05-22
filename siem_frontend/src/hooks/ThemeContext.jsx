import { createContext, useContext, useState, useEffect } from 'react'

const ThemeContext = createContext()

export const THEMES = ['dark', 'light', 'cyber', 'neon', 'ocean', 'obsidian', 'graphite']

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => localStorage.getItem('siem-theme') || 'dark')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('siem-theme', theme)
  }, [theme])

  const toggle = () => {
    setTheme(t => {
      const nextIdx = (THEMES.indexOf(t) + 1) % THEMES.length
      return THEMES[nextIdx]
    })
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle, themes: THEMES }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return useContext(ThemeContext)
}
