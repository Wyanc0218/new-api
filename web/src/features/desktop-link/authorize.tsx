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
import { useMutation } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Button } from '@/components/ui/button'
import { AuthLayout } from '@/features/auth/auth-layout'
import { markServerErrorHandled } from '@/lib/handle-server-error'
import { AuthOperationError } from '@/lib/secure-verification'
import { useAuthStore } from '@/stores/auth-store'

import {
  completeDesktopAuthorization,
  currentBrowserIdentity,
  isCurrentBrowserIdentity,
} from './api'

export function DesktopLinkAuthorize(props: { flowToken?: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const identity = useRef(currentBrowserIdentity()).current
  const userId = useAuthStore((state) => state.auth.user?.id)
  const sessionId = useAuthStore((state) => state.auth.session?.sid)
  const [error, setError] = useState<string>()
  const [callback, setCallback] = useState<string>()
  const operation = useRef<Promise<string> | undefined>(undefined)
  const { mutateAsync } = useMutation({
    mutationFn: async () => {
      if (!props.flowToken || !identity) {
        throw new AuthOperationError(
          'Invalid desktop sign-in link. Start sign-in from Xingyin.'
        )
      }
      return completeDesktopAuthorization(props.flowToken, identity)
    },
    retry: false,
    gcTime: 0,
    meta: { errorToast: false },
  })
  const accountChanged =
    !identity || userId !== identity.userId || sessionId !== identity.sessionId

  useEffect(() => {
    if (!props.flowToken || !identity || accountChanged) return
    let active = true
    // Strict Mode can re-run effects; a one-time flow must never be submitted twice.
    operation.current ??= mutateAsync()
    const pending = operation.current
    void (async () => {
      try {
        const target = await pending
        if (!active || !isCurrentBrowserIdentity(identity)) return
        setCallback(target)
        await navigate({ href: target, reloadDocument: true, replace: true })
      } catch (failure) {
        if (!active) return
        markServerErrorHandled(failure)
        setError(AuthOperationError.from(failure).message)
      }
    })()
    return () => {
      active = false
    }
  }, [props.flowToken, identity, accountChanged, mutateAsync, navigate])

  let message = error
  if (!props.flowToken) {
    message = t('Invalid desktop sign-in link. Start sign-in from Xingyin.')
  } else if (accountChanged) {
    message = t(
      'The browser account changed. Return to Xingyin and sign in again.'
    )
  }

  return (
    <AuthLayout>
      <main aria-live='polite' className='space-y-4 text-center'>
        <meta name='referrer' content='no-referrer' />
        <h2 className='text-2xl font-semibold tracking-tight'>
          {t('Sign in to Xingyin')}
        </h2>
        {message ? (
          <ErrorState
            title={t('Desktop sign-in interrupted')}
            description={t(message)}
            action={
              <Button
                variant='outline'
                role='link'
                nativeButton={false}
                render={<Link to='/' />}
              >
                {t('Back to home')}
              </Button>
            }
          />
        ) : (
          <>
            <LoadingState
              message={
                callback
                  ? t('Returning to Xingyin…')
                  : t('Completing desktop sign-in…')
              }
            />
            <p className='text-muted-foreground text-sm'>
              {t(
                'Your platform account will be used in the desktop app. Keep Xingyin open.'
              )}
            </p>
            {callback && (
              <Button
                role='link'
                nativeButton={false}
                render={<a href={callback} referrerPolicy='no-referrer' />}
              >
                {t('Return to Xingyin')}
              </Button>
            )}
          </>
        )}
      </main>
    </AuthLayout>
  )
}
