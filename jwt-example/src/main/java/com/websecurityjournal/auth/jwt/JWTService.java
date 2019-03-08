package com.websecurityjournal.auth.jwt;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.NoSuchPaddingException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Service for generating and validating JWT tokens
 * 
 * @author varun
 *
 */
public class JWTService
{
    /**
     * Generates JWT token with given userId as claim.
     * 
     * @param userId
     *            userId o be added as claim
     * @param privateKeyString
     *            private key for signing
     * @return Jwt token
     * 
     * @throws IllegalArgumentException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public String createJWT(String userId, String privateKeyString) throws IllegalArgumentException,
            UnsupportedEncodingException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        RSAPrivateKey privateKey = (RSAPrivateKey) getPrivateKey(privateKeyString);
        RSAPublicKey publicKey = null;

        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

        long currentTimeInSeconds = System.currentTimeMillis() / 1000;
        long expiryTime = currentTimeInSeconds + 600; // 10 mins
        String token = JWT.create().withClaim("userId", userId).withClaim("expiry", expiryTime).sign(algorithm);
        return token;
    }

    /**
     * validates JWT and extract userId from the claim if token is valid.
     * 
     * @param jwt
     *            JWT token
     * @param publicKeyString
     *            public key for signature validation
     * @return userId xtracted from the JWT
     * @throws JWTException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public String validateJWT(String jwt, String publicKeyString)
            throws JWTException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(publicKeyString);

        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
        JWTVerifier verifier = JWT.require(algorithm).build();

        DecodedJWT decodedJwt = verifier.verify(jwt);
        String userId = decodedJwt.getClaim("userId").asString();
        Long expiry = decodedJwt.getClaim("expiry").asLong();
        if (expiry != null)
        {
            long currentTimeInSeconds = System.currentTimeMillis() / 1000;
            if (currentTimeInSeconds > expiry)
            {
                throw new JWTException("Token expired");
            }
        }

        return userId;
    }

    private PublicKey getPublicKey(String publicKeyString)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));

        PublicKey pk = kf.generatePublic(ks);
        return pk;
    }

    private PrivateKey getPrivateKey(String privateKeyString)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));

        PrivateKey pk = kf.generatePrivate(ks);
        return pk;
    }
}
