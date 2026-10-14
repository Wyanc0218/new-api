/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StrictMode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { OtpForm } from '@/features/auth/otp/components/otp-form'
import { api } from '@/lib/api'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { validatedDesktopCallback } from '../api'
import { DesktopLinkAuthorize } from '../authorize'
import { desktopLinkSearch, requireDesktopLinkSession } from '../route-guard'

const flow = 'f'.repeat(43)
const returnPath = `/link/authorize?flow_token=${flow}`
const callback = `http://127.0.0.1:45431/callback?code=${'c'.repeat(43)}&state=${'s'.repeat(43)}`
const bundle: AuthBundle = {
  access_token: 'test-browser-session',
  token_type: 'Bearer',
  access_expires_at: 9999999999,
  user: { id: 42, username: 'verified-user', role: 1 },
  session: {
    sid: 'test-session',
    current: true,
    login_method: 'password',
    ip: '',
    user_agent: '',
    created_at: 1,
    last_active_at: 1,
    expires_at: 9999999999,
  },
}

function renderAuthorization(entry = returnPath, strict = false) {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  })
  const root = createRootRoute({ component: Outlet })
  const link = createRoute({
    getParentRoute: () => root,
    path: '/link/authorize',
    validateSearch: desktopLinkSearch,
    beforeLoad: ({ search }) => requireDesktopLinkSession(search.flow_token),
    component: function AuthorizationRoute() {
      const search = link.useSearch()
      return (
        <DesktopLinkAuthorize
          key={search.flow_token}
          flowToken={search.flow_token}
        />
      )
    },
  })
  const signIn = createRoute({
    getParentRoute: () => root,
    path: '/sign-in',
    validateSearch: (search: Record<string, unknown>) => ({
      redirect: String(search.redirect ?? ''),
    }),
    component: () => <div>Sign-in page</div>,
  })
  const otp = createRoute({
    getParentRoute: () => root,
    path: '/otp',
    component: OtpForm,
  })
  const home = createRoute({
    getParentRoute: () => root,
    path: '/',
    component: () => <div>Home page</div>,
  })
  const router = createRouter({
    routeTree: root.addChildren([link, signIn, otp, home]),
    history: createMemoryHistory({ initialEntries: [entry] }),
  })
  const externalNavigations: string[] = []
  const originalNavigate = router.navigate.bind(router)
  vi.spyOn(router, 'navigate').mockImplementation((options) => {
    if (options.reloadDocument) {
      externalNavigations.push(String(options.href))
      return Promise.resolve()
    }
    return originalNavigate(options)
  })
  const content = (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  const view = render(strict ? <StrictMode>{content}</StrictMode> : content)
  return { router, externalNavigations, ...view }
}

beforeEach(() => {
  useAuthStore.getState().auth.setBundle(bundle)
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  useAuthStore.getState().auth.reset('complete')
})

it('uses the browser session once under Strict Mode and returns only the validated authorization code', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { callback_url: callback } },
  })
  const { externalNavigations } = renderAuthorization(returnPath, true)
  await waitFor(() => expect(externalNavigations).toEqual([callback]))
  expect(post).toHaveBeenCalledTimes(1)
  expect(post).toHaveBeenCalledWith(
    '/api/link/v1/auth/complete',
    { flow_token: flow },
    expect.objectContaining({
      singleUseAuthorization: true,
      skipErrorHandler: true,
      signal: expect.any(AbortSignal),
    })
  )
  expect(
    screen.getByRole('link', { name: 'Return to Xingyin' })
  ).toHaveAttribute('href', callback)
  expect(screen.queryByText(bundle.access_token)).not.toBeInTheDocument()
})

it('redirects anonymous users to existing sign-in with the full local return path', async () => {
  useAuthStore.getState().auth.reset('complete')
  const post = vi.spyOn(api, 'post')
  const { router } = renderAuthorization()
  await screen.findByText('Sign-in page')
  expect(router.state.location.search).toEqual({ redirect: returnPath })
  expect(post).not.toHaveBeenCalled()
})

it('does not authorize until existing MFA finishes and preserves the desktop return path', async () => {
  useAuthStore.getState().auth.reset('complete')
  useAuthStore.getState().auth.setPendingLoginVerification({
    challenge: {
      require_verification: true,
      flow_token: 'mfa-challenge',
      expires_at: Math.floor(Date.now() / 1000) + 300,
      methods: [{ method: '2fa', available: true }],
    },
    redirectTo: returnPath,
  })
  const post = vi.spyOn(api, 'post').mockImplementation(async (url) => {
    if (url === '/api/link/v1/auth/complete') {
      return { data: { success: true, data: { callback_url: callback } } }
    }
    return { data: { success: true, data: bundle } }
  })
  const { externalNavigations } = renderAuthorization('/otp')
  const user = userEvent.setup()
  const input = await screen.findByLabelText(
    'Authenticator code or backup code'
  )
  expect(post).not.toHaveBeenCalled()
  await user.type(input, '123456')
  await user.keyboard('{Enter}')
  await waitFor(() => expect(externalNavigations).toEqual([callback]))
  expect(post).toHaveBeenCalledTimes(2)
  expect(useAuthStore.getState().auth.user?.id).toBe(bundle.user.id)
})

it.each([
  '/link/authorize',
  '/link/authorize?flow_token=bad',
  '/link/authorize?flow_token=https%3A%2F%2Fevil.example',
])('rejects malformed entry %s without a request', async (entry) => {
  const post = vi.spyOn(api, 'post')
  const { externalNavigations } = renderAuthorization(entry)
  await screen.findByText(
    'Invalid desktop sign-in link. Start sign-in from Xingyin.'
  )
  expect(post).not.toHaveBeenCalled()
  expect(externalNavigations).toEqual([])
  const user = userEvent.setup()
  screen.getByRole('link', { name: 'Back to home' }).focus()
  await user.keyboard('{Enter}')
  await screen.findByText('Home page')
})

it.each(['LINK_UNAUTHORIZED', 'LINK_NOT_CONFIGURED', 'LINK_INTERNAL_ERROR'])(
  'shows %s without replaying a one-time flow',
  async (code) => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({
      data: { success: false, code, message: 'sensitive server detail' },
    })
    const { externalNavigations } = renderAuthorization()
    await screen.findByText('Desktop sign-in interrupted')
    expect(post).toHaveBeenCalledTimes(1)
    expect(externalNavigations).toEqual([])
    expect(
      screen.queryByText('sensitive server detail')
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Retry' })
    ).not.toBeInTheDocument()
  }
)

it.each(['account change', 'unmount'])(
  'ignores a late result after %s',
  async (change) => {
    let finish:
      | ((value: {
          data: { success: boolean; data: { callback_url: string } }
        }) => void)
      | undefined
    const pending = new Promise<{
      data: { success: boolean; data: { callback_url: string } }
    }>((resolve) => {
      finish = resolve
    })
    const post = vi.spyOn(api, 'post').mockReturnValue(pending)
    const view = renderAuthorization()
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    if (change === 'unmount') view.unmount()
    else {
      act(() =>
        useAuthStore.getState().auth.setBundle({
          ...bundle,
          user: { ...bundle.user, id: 43 },
          session: { ...bundle.session, sid: 'other-session' },
        })
      )
    }
    await act(async () => {
      finish?.({ data: { success: true, data: { callback_url: callback } } })
      await pending
    })
    expect(view.externalNavigations).toEqual([])
    if (change === 'account change') {
      expect(post.mock.calls[0]?.[2]?.signal?.aborted).toBe(true)
      expect(
        screen.getByText(
          'The browser account changed. Return to Xingyin and sign in again.'
        )
      ).toBeVisible()
    }
  }
)

it('rejects an unsafe callback from a successful server response', async () => {
  vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: { callback_url: 'https://evil.example/callback' },
    },
  })
  const { externalNavigations } = renderAuthorization()
  await screen.findByText('Desktop sign-in interrupted')
  expect(externalNavigations).toEqual([])
  expect(
    screen.queryByRole('link', { name: 'Return to Xingyin' })
  ).not.toBeInTheDocument()
})

it.each([
  callback.replace('127.0.0.1', '[::1]'),
  callback.replace(':45431', ':80'),
])('accepts the explicitly supported loopback destination %s', (target) => {
  expect(validatedDesktopCallback(target)).toBe(target)
})

it.each([
  callback.replace('http:', 'https:'),
  callback.replace('127.0.0.1', 'localhost'),
  callback.replace('127.0.0.1', '127.0.0.2'),
  callback.replace('127.0.0.1', '2130706433'),
  callback.replace('127.0.0.1', '127.0.0.1.evil.example'),
  callback.replace('127.0.0.1', 'user@127.0.0.1'),
  callback.replace(':45431', ''),
  callback.replace(':45431', ':65536'),
  callback.replace(':45431', ':0'),
  callback.replace('/callback?', '/other?'),
  callback.replace('/callback?', '/%63allback?'),
  `${callback}#fragment`,
  `${callback}&code=duplicate`,
  `${callback}&extra=secret`,
  callback.replace('state=', 'redirect='),
  callback.replace('code=', 'code=%0A'),
  ` ${callback}`,
  `${callback}\n`,
  null,
])('rejects a non-protocol callback %s', (target) => {
  expect(() => validatedDesktopCallback(target)).toThrow(
    'Invalid desktop callback'
  )
})
