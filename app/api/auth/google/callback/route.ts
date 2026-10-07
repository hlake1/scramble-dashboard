import { NextRequest, NextResponse } from 'next/server'
import { createAdminSupabaseClient } from '@/lib/supabase'

/**
 * GET /api/auth/google/callback
 * 
 * OAuth callback from Google. Exchanges auth code for tokens and stores them.
 * 
 * Query params:
 *   code: string — authorization code from Google
 *   state: string — clientId (passed during initiate)
 *   error?: string — if present, OAuth was denied
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const code = searchParams.get('code')
    const state = searchParams.get('state') // clientId
    const error = searchParams.get('error')

    // User denied access
    if (error) {
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=${encodeURIComponent(error)}`
      )
    }

    if (!code || !state) {
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=missing_code_or_state`
      )
    }

    const clientId = decodeURIComponent(state)

    // Exchange code for tokens
    const tokenResponse = await exchangeCodeForToken(code)
    if (!tokenResponse) {
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=token_exchange_failed`
      )
    }

    const {
      access_token,
      refresh_token,
      expires_in,
      scope,
      id_token,
    } = tokenResponse

    // Get Google account info. Try the userinfo endpoint first; if that fails,
    // fall back to decoding the OIDC id_token (which contains email + sub).
    let googleProfile = await getGoogleProfile(access_token)
    if (!googleProfile && id_token) {
      googleProfile = decodeIdToken(id_token)
    }
    if (!googleProfile || !googleProfile.email) {
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=profile_fetch_failed`
      )
    }

    // Store in Supabase
    const supabase = createAdminSupabaseClient()
    const tokenExpiresAt = new Date(Date.now() + expires_in * 1000).toISOString()

    const { error: upsertError } = await supabase
      .from('google_oauth_connections')
      .upsert([
        {
          client_id: clientId,
          google_account_email: googleProfile.email,
          google_account_id: googleProfile.id,
          access_token,
          refresh_token,
          token_expires_at: tokenExpiresAt,
          granted_scopes: scope,
          is_active: true,
          last_used_at: new Date().toISOString(),
        },
      ])

    if (upsertError) {
      console.error('[OAuth callback] Supabase upsert failed:', upsertError)
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=db_error`
      )
    }

    // Mark the client's profile as google_connected (best-effort)
    await supabase
      .from('scramble_users')
      .update({ google_connected: true, updated_at: new Date().toISOString() })
      .eq('email', clientId)

    // Log success
    await logAuditEvent(supabase, clientId, 'oauth_connected', {
      email: googleProfile.email,
      scopes: scope.split(' '),
    })

    // Redirect back to onboarding with success
    return NextResponse.redirect(
      `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_success=true&email=${encodeURIComponent(clientId)}`
    )
  } catch (error) {
    console.error('[OAuth callback]', error)
    return NextResponse.redirect(
      `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=internal_error`
    )
  }
}

/**
 * Exchange Google authorization code for access + refresh tokens
 */
async function exchangeCodeForToken(code: string) {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET
    const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/google/callback`

    if (!clientId || !clientSecret) {
      throw new Error('Missing Google OAuth secrets')
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

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.statusText}`)
    }

    return await response.json()
  } catch (error) {
    console.error('[Token exchange]', error)
    return null
  }
}

/**
 * Fetch Google profile info (email, id) via the OIDC userinfo endpoint.
 */
async function getGoogleProfile(accessToken: string) {
  try {
    // Use the OpenID Connect userinfo endpoint (works with userinfo.email scope)
    const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    if (!response.ok) {
      throw new Error(`Profile fetch failed: ${response.statusText}`)
    }

    const data = await response.json()
    return {
      email: data.email,
      id: data.sub || data.id,
      name: data.name,
    }
  } catch (error) {
    console.error('[Google profile fetch]', error)
    return null
  }
}

/**
 * Decode the email + sub from a Google OIDC id_token (JWT) without verifying
 * the signature. Safe here because the token came directly from Google's
 * token endpoint over HTTPS in this same request.
 */
function decodeIdToken(idToken: string) {
  try {
    const payload = idToken.split('.')[1]
    const decoded = JSON.parse(
      Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    )
    return {
      email: decoded.email as string,
      id: (decoded.sub || decoded.email) as string,
      name: (decoded.name || '') as string,
    }
  } catch (error) {
    console.error('[decode id_token]', error)
    return null
  }
}

/**
 * Log audit event
 */
async function logAuditEvent(supabase: any, clientId: string, eventType: string, details: any) {
  try {
    // First get the connection ID
    const { data: connection } = await supabase
      .from('google_oauth_connections')
      .select('id')
      .eq('client_id', clientId)
      .single()

    if (!connection) return

    await supabase.from('google_oauth_audit').insert([
      {
        connection_id: connection.id,
        event_type: eventType,
        details,
      },
    ])
  } catch (error) {
    console.error('[Audit log]', error)
  }
}
