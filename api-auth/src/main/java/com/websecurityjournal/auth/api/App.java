package com.websecurityjournal.auth.api;

import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * Main class
 * 
 * @author varun
 */
public class App
{
    private static Logger LOG = Logger.getLogger(App.class.getName());

    public static void main(String[] args)
    {
        KeyGeneratorService keyService = new KeyGeneratorService();

        String apiKey = keyService.generateRandomApiKey();
        try
        {
            String secretKey = keyService.generateRandomSecretKey();
            System.out.println("APIKEY : " + apiKey);
            System.out.println("SECRETKEY : " + secretKey);

            long timestamp = System.currentTimeMillis();
            String timestampString = String.valueOf(timestamp);
            String uri = "https://test.domain.com/api/testApi?param1=A&param2=B";
            String httpMethod = "GET";
            Map<String, String> postparamsMap = Collections.emptyMap();

            ApiAuthService service = new ApiAuthService();
            String hmac = service.getHmacHash(secretKey, apiKey, uri, timestampString, postparamsMap, httpMethod);
            // httpMethod, version);
            LOG.info("Hmac calculated: " + hmac);
        }
        catch (NoSuchAlgorithmException | ApiKeyException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
