import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from '../src/App'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
})

const Wrapper = ({ children }: { children: React.ReactNode }) => (
  <BrowserRouter>
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  </BrowserRouter>
)

describe('App (Phase 1 scaffold)', () => {
  it('renders the platform title', () => {
    render(<App />, { wrapper: Wrapper })
    expect(screen.getByText('AI DevSecOps Platform')).toBeInTheDocument()
  })

  it('renders the phase completion indicator', () => {
    render(<App />, { wrapper: Wrapper })
    expect(screen.getByText(/Phase 1/i)).toBeInTheDocument()
  })

  it('renders the API health link', () => {
    render(<App />, { wrapper: Wrapper })
    const link = screen.getByRole('link', { name: /api health/i })
    expect(link).toHaveAttribute('href', '/api/health')
  })

  it('renders the API docs link', () => {
    render(<App />, { wrapper: Wrapper })
    const link = screen.getByRole('link', { name: /api docs/i })
    expect(link).toHaveAttribute('href', '/api/docs')
  })
})
