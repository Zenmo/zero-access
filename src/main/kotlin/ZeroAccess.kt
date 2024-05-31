package com.zenmo.zeroaccess;

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.SignedJWT
import java.util.*


// found at https://keycloak.zenmo.com/realms/zenmo/protocol/openid-connect/certs
const val defaultJwk = """
{
    "kid": "hN_HaBnYl-n3wae9APMVa9RaR6BdN-3eHAHvVZT_3So",
    "kty": "OKP",
    "alg": "EdDSA",
    "use": "sig",
    "crv": "Ed25519",
    "x": "jmcE7tddPunTe6SbvuaNaeMQJk0bOcdYey2YeU_8lyM"
}
"""

/**
 * Check if the role is present in the token
 *
 * @param role The role to check
 * @param jwt The token to inspect
 * @param jwk The public key to use for verification of the token.
 * If jwk is null, fall back to key from environment variable ROLE_JWK.
 * If that is not set, fall back to the one hardcoded in this package.
 */
@JvmOverloads
fun hasRole(role: String, jwt: String, jwk: String? = null): Boolean {
    try {
        return hasRoleImpl(role, jwt, jwk)
    } catch (e: ZeroAccessException) {
        throw e
    } catch (e: Throwable) {
        throw ZeroAccessException("Invalid ID token: ${e.message}", e)
    }
}

private fun hasRoleImpl(role: String, jwt: String, jwk: String?): Boolean {
    val key = OctetKeyPair.parse(resolveJwk(jwk))
    val signedJwt = SignedJWT.parse(jwt)

    if (signedJwt.jwtClaimsSet.expirationTime.before(Date())) {
        throw ZeroAccessException("ID Token has expired")
    }

    val verifier: JWSVerifier = Ed25519Verifier(key)
    val isValid = verifier.verify(signedJwt.header, signedJwt.signingInput, signedJwt.signature)
    if (!isValid) {
        throw ZeroAccessException("ID Token does not comply with public key")
    }

    val realmRoles = signedJwt.jwtClaimsSet.getListClaim("realm_roles") ?: emptyList();

    return realmRoles.contains(role)
}

private fun resolveJwk(jwk: String?): String {
    if (jwk != null) {
        return jwk
    }

    val envJwk = System.getenv("ROLE_JWK")
    if (envJwk != null) {
        return envJwk
    }

    return defaultJwk
}
