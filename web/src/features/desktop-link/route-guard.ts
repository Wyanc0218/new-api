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
import { redirect } from '@tanstack/react-router'
import { z } from 'zod'

import { resolveAuthentication } from '@/lib/auth-session'

import { currentBrowserIdentity } from './api'

export const desktopLinkSearch = z.object({
  flow_token: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional()
    .catch(undefined),
})

export async function requireDesktopLinkSession(
  flowToken?: string
): Promise<void> {
  if (!flowToken) return
  await resolveAuthentication()
  if (!currentBrowserIdentity()) {
    throw redirect({
      to: '/sign-in',
      search: {
        redirect: `/link/authorize?flow_token=${encodeURIComponent(flowToken)}`,
      },
      replace: true,
    })
  }
}
