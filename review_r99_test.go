package traefikoidc

import "testing"

// TestValidateAzureTokensRS_OpaqueNoIDToken_FailsClosed regresses the Azure
// path accepting an opaque (non-JWT) access token with NO ID token as
// authenticated with zero verification (previously `return true,false,false`
// at validateAzureTokensRS's opaque branch). It must now fail closed and
// mirror validateStandardTokensRS: refresh if possible, else force
// re-authentication — regardless of allowOpaqueTokens (an ID token is
// needed to corroborate, and introspection only validates activity, not
// that this session owns the token).
func TestValidateAzureTokensRS_OpaqueNoIDToken_FailsClosed(t *testing.T) {
	for _, allowOpaque := range []bool{false, true} {
		oidc := &TraefikOidc{allowOpaqueTokens: allowOpaque}

		// No refresh token available -> must force re-authentication.
		rs := &requestState{
			authenticated: true,
			accessToken:   "opaque-access-00000000", // no dots -> opaque
		}
		auth, refresh, expired := oidc.validateAzureTokensRS(rs)
		if auth || refresh || !expired {
			t.Fatalf("allowOpaque=%v, no refresh: want fail-closed (false,false,true), got (auth=%v,refresh=%v,reauth=%v)",
				allowOpaque, auth, refresh, expired)
		}

		// Refresh token available -> must prefer refresh, still not auth.
		rs2 := &requestState{
			authenticated: true,
			accessToken:   "opaque-access-00000000",
			refreshToken:  "refresh-1111",
		}
		auth, refresh, expired = oidc.validateAzureTokensRS(rs2)
		if auth || !refresh || expired {
			t.Fatalf("allowOpaque=%v, with refresh: want (false,true,false) refresh path, got (auth=%v,refresh=%v,reauth=%v)",
				allowOpaque, auth, refresh, expired)
		}
	}
}
