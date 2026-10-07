import { NextRequest, NextResponse } from 'next/server'
import { createAdminSupabaseClient } from '@/lib/supabase'

/**
 * GET /api/auth/google/callback
 *
 * OAuth callback from Google — follows the Tweak pattern:
 * 1. Validate state parameter
 * 2. Exchange auth code for tokens
 * 3. Get Google profile
 * 4. Store tokens in Supabase (insert only, let unique constraint handle updates)
 * 5. Return HTML confirmation page (not a redirect — keeps tokens server-side)
 *
 * Query params:
 *   code: string — authorization code from Google
 *   state: string — clientId (passed during initiate)
 *   error?: string — if present, OAuth was denied
 */
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  const state = searchParams.get('state') // clientId
  const error = searchParams.get('error')

  console.log('[OAuth Callback] Starting - code:', !!code, 'state:', !!state, 'error:', error)
  console.log('[OAuth Callback] Env vars - GOOGLE_CLIENT_ID:', !!process.env.GOOGLE_CLIENT_ID, 'GOOGLE_CLIENT_SECRET:', !!process.env.GOOGLE_CLIENT_SECRET, 'NEXT_PUBLIC_APP_URL:', process.env.NEXT_PUBLIC_APP_URL)

  // User denied access
  if (error) {
    console.log('[OAuth Callback] User denied access:', error)
    return htmlResponse(
      `<p>Google sign-in was cancelled: <code>${escapeHtml(error)}</code></p>
       <p><a href="${escapeHtml(process.env.NEXT_PUBLIC_APP_URL || '')}/onboarding">Try again</a></p>`,
      200
    )
  }

  if (!code || !state) {
    console.log('[OAuth Callback] Missing code or state')
    return htmlResponse(
      '<p>Missing code or state. Close this tab and click "Connect" again.</p>',
      400
    )
  }

  const clientId = decodeURIComponent(state)

  console.log('[OAuth Callback] clientId:', clientId)
  // Exchange code for tokens
  console.log('[OAuth Callback] Attempting token exchange...')
  const tokenResponse = await exchangeCodeForToken(code)
  if (!tokenResponse) {
    console.log('[OAuth Callback] Token exchange failed - tokenResponse is null')
    return htmlResponse(
      '<p>Couldn\'t exchange authorization code for tokens. Close this tab and try again.</p>',
      502
    )
  }

  const { access_token, refresh_token, expires_in, scope, id_token } = tokenResponse

  // Get Google profile
  let googleProfile = await getGoogleProfile(access_token)
  if (!googleProfile && id_token) {
    googleProfile = decodeIdToken(id_token)
  }
  if (!googleProfile || !googleProfile.email) {
    return htmlResponse(
      '<p>Couldn\'t fetch your Google profile. Close this tab and try again.</p>',
      502
    )
  }

  // Store tokens in Supabase
  const supabase = createAdminSupabaseClient()
  const stored = await storeGoogleConnection(supabase, {
    clientId,
    googleEmail: googleProfile.email,
    googleId: googleProfile.id,
    accessToken: access_token,
    refreshToken: refresh_token,
    expiresIn: expires_in,
    grantedScopes: scope,
  })

  if (!stored) {
    return htmlResponse(
      '<p>Couldn\'t save your connection. Close this tab and try again.</p>',
      502
    )
  }

  // Update user profile (best-effort, don't block on it)
  supabase
    .from('scramble_users')
    .update({ google_connected: true, updated_at: new Date().toISOString() })
    .eq('email', clientId)
    .catch(() => null)

  // Return HTML confirmation (never redirect away — keeps tokens server-side)
  return htmlResponse(`
    <!doctype html><meta charset="utf-8">
    <body style="font-family:system-ui,sans-serif;max-width:420px;margin:15vh auto;text-align:center;color:#111;">
      <p style="font-size:2rem;margin:0;">✓</p>
      <h1 style="font-size:1.25rem;">Connected as ${escapeHtml(googleProfile.email)}</h1>
      <p style="color:#555;">You can close this tab and go back to Scramble.</p>
    </body>
  `, 200)
}

/**
 * Helper: HTML response (like Tweak's pattern)
 */
function htmlResponse(body: string, status: number) {
  return new NextResponse(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  })
}

/**
 * Helper: Escape HTML (prevent XSS)
 */
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  }
  return text.replace(/[&<>"']/g, (c) => map[c])
}

/**
 * Exchange Google authorization code for access + refresh tokens
 */
async function exchangeCodeForToken(code: string): Promise<any | null> {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET
    const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/google/callback`

    if (!clientId || !clientSecret) {
      console.error('[Token exchange] Missing Google OAuth env vars')
      return null
    }

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }).toString(),
    })

    const data = await response.json()
    if (!response.ok) {
      console.error('[Token exchange] Google error:', data.error, data.error_description)
      return null
    }

    return data
  } catch (error) {
    console.error('[Token exchange] Network error:', error)
    return null
  }
}

/**
 * Fetch Google profile info (email, id) via the OIDC userinfo endpoint
 */
async function getGoogleProfile(accessToken: string): Promise<{ email: string; id: string; name: string } | null> {
  try {
    const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    if (!response.ok) {
      console.error('[Profile fetch] HTTP error:', response.status)
      return null
    }

    const data = await response.json()
    return {
      email: data.email as string,
      id: (data.sub || data.id) as string,
      name: data.name as string,
    }
  } catch (error) {
    console.error('[Profile fetch] Error:', error)
    return null
  }
}

/**
 * Decode email + sub from Google OIDC id_token (no signature verification needed
 * because token came directly from Google's token endpoint over HTTPS).
 */
function decodeIdToken(idToken: string): { email: string; id: string; name: string } | null {
  try {
    const payload = idToken.split('.')[1]
    if (!payload) return null
    const decoded = JSON.parse(
      Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    )
    return {
      email: decoded.email as string,
      id: (decoded.sub || decoded.email) as string,
      name: (decoded.name || '') as string,
    }
  } catch (error) {
    console.error('[Decode id_token] Error:', error)
    return null
  }
}

/**
 * Store Google connection in Supabase using insert + on conflict update pattern
 * (Tweak-inspired: simpler than upsert, no syntax issues)
 */
async function storeGoogleConnection(
  supabase: any,
  params: {
    clientId: string
    googleEmail: string
    googleId: string
    accessToken: string
    refreshToken: string
    expiresIn: number
    grantedScopes: string
  }
): Promise<boolean> {
  try {
    const { clientId, googleEmail, googleId, accessToken, refreshToken, expiresIn, grantedScopes } = params
    const now = new Date().toISOString()
    const tokenExpiresAt = new Date(Date.now() + expiresIn * 1000).toISOString()

    // Try insert first (most common path — first connection or update after delete)
    const { error: insertError, data: insertData } = await supabase
      .from('google_oauth_connections')
      .insert([
        {
          client_id: clientId,
          google_account_email: googleEmail,
          google_account_id: googleId,
          access_token: accessToken,
          refresh_token: refreshToken,
          token_expires_at: tokenExpiresAt,
          granted_scopes: grantedScopes,
          is_active: true,
          last_used_at: now,
          created_at: now,
          updated_at: now,
        },
      ])
      .select()

    if (!insertError && insertData?.length) {
      console.log('[OAuth] Successfully inserted new connection')
      return true
    }

    // If insert failed due to unique constraint (record already exists), update it instead
    if (insertError?.code === '23505') {
      console.log('[OAuth] Record exists, updating...')
      const { error: updateError } = await supabase
        .from('google_oauth_connections')
        .update({
          google_account_email: googleEmail,
          google_account_id: googleId,
          access_token: accessToken,
          refresh_token: refreshToken,
          token_expires_at: tokenExpiresAt,
          granted_scopes: grantedScopes,
          is_active: true,
          last_used_at: now,
          updated_at: now,
        })
        .eq('client_id', clientId)

      if (updateError) {
        console.error('[OAuth] Update failed:', updateError)
        return false
      }
      console.log('[OAuth] Successfully updated connection')
      return true
    }

    // Other errors
    console.error('[OAuth] Insert failed:', insertError)
    return false
  } catch (error) {
    console.error('[Store connection] Error:', error)
    return false
  }
}
