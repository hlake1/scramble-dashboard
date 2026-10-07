import { NextRequest, NextResponse } from 'next/server'
import { createAdminSupabaseClient } from '@/lib/supabase'

/**
 * GET /api/test/google-access
 * 
 * Test endpoint to verify we can access Google APIs using stored OAuth tokens
 * Query params:
 *   client_id: string — the email of the client to test (e.g., info@onlyvans4u.com)
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const clientId = searchParams.get('client_id') || 'info@onlyvans4u.com'

    console.log('[Test Google Access] Testing access for client:', clientId)

    // Get the stored OAuth tokens from Supabase
    const supabase = createAdminSupabaseClient()
    const { data: connection, error: fetchError } = await supabase
      .from('google_oauth_connections')
      .select('access_token, refresh_token, token_expires_at, google_account_email, granted_scopes')
      .eq('client_id', clientId)
      .single()

    if (fetchError || !connection) {
      console.error('[Test Google Access] Failed to fetch OAuth connection:', fetchError)
      return NextResponse.json(
        { error: 'No OAuth connection found for this client' },
        { status: 404 }
      )
    }

    console.log('[Test Google Access] Found connection for:', connection.google_account_email)
    console.log('[Test Google Access] Granted scopes:', connection.granted_scopes)

    let accessToken = connection.access_token
    const tokenExpiresAt = new Date(connection.token_expires_at)
    const now = new Date()

    // Check if token is expired and refresh if needed
    if (now >= tokenExpiresAt) {
      console.log('[Test Google Access] Token expired, refreshing...')
      accessToken = await refreshAccessToken(connection.refresh_token)
      if (!accessToken) {
        return NextResponse.json(
          { error: 'Failed to refresh access token' },
          { status: 401 }
        )
      }
      console.log('[Test Google Access] Token refreshed successfully')
    } else {
      console.log('[Test Google Access] Token still valid, expires at:', tokenExpiresAt)
    }

    // Test 1: Get user profile from Google
    console.log('[Test Google Access] Testing Google API: userinfo endpoint')
    const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    if (!profileResponse.ok) {
      console.error('[Test Google Access] Profile fetch failed:', profileResponse.status, profileResponse.statusText)
      return NextResponse.json(
        { error: `Google API access failed: ${profileResponse.statusText}` },
        { status: 401 }
      )
    }

    const userProfile = await profileResponse.json()
    console.log('[Test Google Access] Successfully accessed Google APIs')
    console.log('[Test Google Access] User email:', userProfile.email)
    console.log('[Test Google Access] User name:', userProfile.name)

    // Test 2: Check available Google APIs based on granted scopes
    const tests = {
      googleProfile: {
        status: 'success',
        email: userProfile.email,
        name: userProfile.name,
        picture: userProfile.picture,
      },
      infrastructure: {
        tokenValid: true,
        tokenExpiresAt: tokenExpiresAt.toISOString(),
        grantedScopes: connection.granted_scopes.split(' '),
        canAccessAnalytics: connection.granted_scopes.includes('analytics'),
        canAccessSearchConsole: connection.granted_scopes.includes('webmasters'),
        canAccessAds: connection.granted_scopes.includes('adwords'),
      },
    }

    console.log('[Test Google Access] All infrastructure tests passed')
    return NextResponse.json({
      success: true,
      message: 'Successfully connected to Google APIs',
      tests,
      recommendation: 'Ready to build data collection and campaign management bot',
    })
  } catch (error) {
    console.error('[Test Google Access] Unexpected error:', error)
    return NextResponse.json(
      { error: 'Internal server error', details: String(error) },
      { status: 500 }
    )
  }
}

/**
 * Refresh an expired Google OAuth token using the refresh token
 */
async function refreshAccessToken(refreshToken: string): Promise<string | null> {
  try {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID!,
        client_secret: process.env.GOOGLE_CLIENT_SECRET!,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }).toString(),
    })

    if (!response.ok) {
      console.error('[Refresh Token] Failed:', response.status, response.statusText)
      return null
    }

    const data = await response.json()
    return data.access_token
  } catch (error) {
    console.error('[Refresh Token] Error:', error)
    return null
  }
}
