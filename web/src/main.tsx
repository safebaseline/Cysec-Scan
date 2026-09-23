import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App, { SSEProvider } from './App.tsx'

// 主题预热（渲染前应用，避免切换闪变；可选 dark / gray / light）
document.documentElement.dataset.theme = localStorage.getItem('theme') || 'dark'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SSEProvider>
      <App />
    </SSEProvider>
  </StrictMode>,
)
