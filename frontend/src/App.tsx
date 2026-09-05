import React from 'react'

export const App: React.FC = () => {
  return (
    <div style={{ fontFamily: 'system-ui, -apple-system, sans-serif', padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>AIVARA</h1>
      <p style={{ color: '#666', fontStyle: 'italic' }}>Don't Trust the AI Pipeline. Verify It.</p>
      <div style={{ border: '1px solid #ccc', borderRadius: '8px', padding: '1rem', marginTop: '1.5rem' }}>
        <h3>Platform Status</h3>
        <p>Phase 2: Repository Foundation & Minimal Backend Skeleton Initialized.</p>
        <p>Backend Service: <code>http://127.0.0.1:8000/health</code></p>
      </div>
    </div>
  )
}
