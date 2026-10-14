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
import { api } from '@/lib/api'
import {
  authRequestOptions,
  authResult,
  AuthOperationError,
} from '@/lib/secure-verification'
import { useAuthStore } from '@/stores/auth-store'

export type BrowserIdentity = { userId: number; sessionId: string }

export function currentBrowserIdentity(): BrowserIdentity | null {
  const auth = useAuthStore.getState().auth
  if (!auth.user || !auth.session || !auth.accessToken) return null
  return { userId: auth.user.id, sessionId: auth.session.sid }
}

export function isCurrentBrowserIdentity(identity: BrowserIdentity): boolean {
  const current = currentBrowserIdentity()
  return (
    current?.userId === identity.userId &&
    current.sessionId === identity.sessionId
  )
}

/** Only the explicit local callback shapes accepted by the desktop protocol. */
export function validatedDesktopCallback(value: unknown): string {
  if (typeof value !== 'string' || /[\s\\]/.test(value)) {
    throw new Error('Invalid desktop callback')
  }
  const origin =
    /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9]\d{0,4})\/callback\?/.exec(value)
  if (!origin || Number(origin[2]) > 65535) {
    throw new Error('Invalid desktop callback')
  }
  const url = new URL(value)
  const keys = [...url.searchParams.keys()]
  if (
    url.username ||
    url.password ||
    url.hash ||
    url.pathname !== '/callback' ||
    keys.length !== 2 ||
    url.searchParams.getAll('code').length !== 1 ||
    url.searchParams.getAll('state').length !== 1 ||
    !/^[A-Za-z0-9_-]{32,256}$/.test(url.searchParams.get('code') ?? '') ||
    !/^[A-Za-z0-9._~-]{43,128}$/.test(url.searchParams.get('state') ?? '')
  ) {
    throw new Error('Invalid desktop callback')
  }
  return value
}

export async function completeDesktopAuthorization(
  flowToken: string,
  identity: BrowserIdentity
): Promise<string> {
  const sessionChanged = () =>
    new AuthOperationError(
      'The browser account changed. Return to Xingyin and sign in again.'
    )
  if (!isCurrentBrowserIdentity(identity)) throw sessionChanged()
  const controller = new AbortController()
  const unsubscribe = useAuthStore.subscribe(() => {
    if (!isCurrentBrowserIdentity(identity)) controller.abort()
  })
  try {
    const result = await authResult<{ callback_url: unknown }>(
      api.post(
        '/api/link/v1/auth/complete',
        { flow_token: flowToken },
        {
          ...authRequestOptions,
          singleUseAuthorization: true,
          timeout: 15_000,
          signal: controller.signal,
        }
      )
    )
    if (controller.signal.aborted || !isCurrentBrowserIdentity(identity)) {
      throw sessionChanged()
    }
    return validatedDesktopCallback(result.callback_url)
  } catch (error) {
    if (controller.signal.aborted || !isCurrentBrowserIdentity(identity)) {
      throw sessionChanged()
    }
    const failure = AuthOperationError.from(error)
    if (failure.code === 'LINK_UNAUTHORIZED') {
      throw new AuthOperationError(
        'This desktop sign-in link has expired or was already used. Start again in Xingyin.'
      )
    }
    if (failure.code === 'LINK_NOT_CONFIGURED') {
      throw new AuthOperationError(
        'Desktop sign-in is not available on this platform yet.'
      )
    }
    throw new AuthOperationError(
      'Desktop sign-in could not be completed. Return to Xingyin and start again.'
    )
  } finally {
    unsubscribe()
  }
}
