cat > app/api/auth/google/callback/route.ts << 'EOF'
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

    console.log('[OAuth callback] Received callback - code present:', !!code, 'state present:', !!state, 'error:', error)
    console.log('[OAuth callback] Env check - GOOGLE_CLIENT_ID:', !!process.env.GOOGLE_CLIENT_ID, 'GOOGLE_CLIENT_SECRET:', !!process.env.GOOGLE_CLIENT_SECRET)

    // User denied access
    if (error) {
      console.log('[OAuth callback] User denied OAuth:', error)
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=${encodeURIComponent(error)}`
      )
    }

    if (!code || !state) {
      console.error('[OAuth callback] Missing code or state - code:', !!code, 'state:', !!state)
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=missing_code_or_state`
      )
    }

    const clientId = decodeURIComponent(state)
    console.log('[OAuth callback] Decoded clientId (email):', clientId)

    // Exchange code for tokens
    console.log('[OAuth callback] Starting token exchange...')
    const tokenResponse = await exchangeCodeForToken(code)
    if (!tokenResponse) {
      console.error('[OAuth callback] Token exchange returned null')
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=token_exchange_failed`
      )
    }

    console.log('[OAuth callback] Token exchange successful - got access_token and refresh_token')
    const {
      access_token,
      refresh_token,
      expires_in,
      scope,
      id_token,
    } = tokenResponse

    // Get Google account info. Try the userinfo endpoint first; if that fails,
    // fall back to decoding the OIDC id_token (which contains email + sub).
    console.log('[OAuth callback] Fetching Google profile...')
    let googleProfile = await getGoogleProfile(access_token)
    if (!googleProfile && id_token) {
      console.log('[OAuth callback] Userinfo endpoint failed, trying id_token decode...')
      googleProfile = decodeIdToken(id_token)
    }
    if (!googleProfile || !googleProfile.email) {
      console.error('[OAuth callback] Could not get email from Google profile')
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_error=profile_fetch_failed`
      )
    }

    console.log('[OAuth callback] Got Google profile - email:', googleProfile.email, 'id:', googleProfile.id)

    // Store in Supabase
    console.log('[OAuth callback] Storing tokens in Supabase...')
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

    console.log('[OAuth callback] Successfully stored tokens in database')

    // Mark the client's profile as google_connected (best-effort)
    console.log('[OAuth callback] Updating user profile to mark google_connected...')
    await supabase
      .from('scramble_users')
      .update({ google_connected: true, updated_at: new Date().toISOString() })
      .eq('email', clientId)

    // Log success
    console.log('[OAuth callback] OAuth flow complete - logging audit event')
    await logAuditEvent(supabase, clientId, 'oauth_connected', {
      email: googleProfile.email,
      scopes: scope.split(' '),
    })

    console.log('[OAuth callback] SUCCESS - redirecting to onboarding with oauth_success')
    // Redirect back to onboarding with success
    return NextResponse.redirect(
      `${process.env.NEXT_PUBLIC_APP_URL}/onboarding?oauth_success=true&email=${encodeURIComponent(clientId)}`
    )
  } catch (error) {
    console.error('[OAuth callback] Unexpected error:', error)
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

    console.log('[Token exchange] Checking env vars - clientId:', !!clientId, 'clientSecret:', !!clientSecret, 'redirectUri:', redirectUri)

    if (!clientId || !clientSecret) {
      throw new Error('Missing Google OAuth secrets')
    }

    console.log('[Token exchange] Making POST to oauth2.googleapis.com/token')
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

    console.log('[Token exchange] Google response status:', response.status)

    if (!response.ok) {
      const errorData = await response.json()
      console.error('[Token exchange] Google returned error:', response.status, errorData.error, errorData.error_description)
      throw new Error(`Token exchange failed: ${response.statusText}`)
    }

    const data = await response.json()
    console.log('[Token exchange] Got token response - has access_token:', !!data.access_token, 'has refresh_token:', !!data.refresh_token, 'has id_token:', !!data.id_token)
    return data
  } catch (error) {
    console.error('[Token exchange] Failed:', error)
    return null
  }
}

/**
 * Fetch Google profile info (email, id) via the OIDC userinfo endpoint.
 */
async function getGoogleProfile(accessToken: string) {
  try {
    console.log('[Profile fetch] Calling openidconnect.googleapis.com/v1/userinfo...')
    // Use the OpenID Connect userinfo endpoint (works with userinfo.email scope)
    const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    console.log('[Profile fetch] Response status:', response.status)

    if (!response.ok) {
      console.error('[Profile fetch] HTTP error:', response.status, response.statusText)
      throw new Error(`Profile fetch failed: ${response.statusText}`)
    }

    const data = await response.json()
    console.log('[Profile fetch] Got profile - email:', data.email, 'id:', data.sub || data.id)
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
    console.log('[Decode id_token] Attempting to decode JWT...')
    const payload = idToken.split('.')[1]
    const decoded = JSON.parse(
      Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    )
    console.log('[Decode id_token] Success - email:', decoded.email, 'id:', decoded.sub || decoded.email)
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
    console.log('[Audit log] Creating audit event for clientId:', clientId, 'eventType:', eventType)
    // First get the connection ID
    const { data: connection } = await supabase
      .from('google_oauth_connections')
      .select('id')
      .eq('client_id', clientId)
      .single()

    if (!connection) {
      console.warn('[Audit log] Connection not found for clientId:', clientId)
      return
    }

    await supabase.from('google_oauth_audit').insert([
      {
        connection_id: connection.id,
        event_type: eventType,
        details,
      },
    ])
    console.log('[Audit log] Audit event logged successfully')
  } catch (error) {
    console.error('[Audit log]', error)
  }
}
