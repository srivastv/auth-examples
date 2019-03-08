package com.websecurityjournal.auth.api;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

/**
 * @author varun
 *
 */
public class KeyGeneratorService
{
    /**
     * Method to generate random secret key for a user. The secret key will be
     * generated using KeyGenerator for HmacSHA256 algorithm and will be of 128
     * bits.
     * 
     * @throws NoSuchAlgorithmException
     */
    public String generateRandomSecretKey() throws NoSuchAlgorithmException
    {
        SecretKey key = null;
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(128);
        key = keyGen.generateKey();

        return Hex.encodeHexString(key.getEncoded());
    }

    public String generateRandomApiKey()
    {
        UUID uniqueID = UUID.randomUUID();
        String apiKey = Base64.getEncoder().encodeToString(uniqueID.toString().getBytes());
        return apiKey;
    }

}
