package com.websecurityjournal.auth.jwt;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;

/**
 * 
 * @author varun
 *
 */
public class App
{
    private static final String TEST_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALmX0B4Ww77jwInApQquS8UH1c34pNwMkw1ajECwGLJf0m9r6f75B2GAgRHxL+9PJgJngwDCvrq/Nm+jb9CWiBb52bCl/IyOxqvbI0J3JR00Vv1JsCjXarLHsYYAbgDUH4KbnKMbIWM4y+eDXRaMuhvgGhzDTP6fukBHHi1yp8/vAgMBAAECgYAURrm+D86i9E78vcdKO3CbvhdlwVyBjf4i31mjV5nbIwzij2+pI5vi0x9GzormIkeMy7JMSvp7fJh96eU1bLzBVgRmLeSJjrQr7pSOUyVF/FT1/AdoYRy96Jbf22cclU+twpXp+Fb2o42uv50qL4COlfk+I17RzHPh89SkpKRqAQJBAO9cYFoZ2cZNK+Qh5jROPtWsZF7d56NYGtjTz9IEVXsqzm/20WQ+1MkhnJVh+xHVdJ0slHFS+Zzoz24v+qX7G6ECQQDGfpgCRx2kzTakUv2YPBWEUUWlaIz707N82oygAUSA2SJ/nDea0gDCdd3C75oGql7yjv6Sup8Q6qs1Xpe5L8GPAkBqo89RlR7PGGarlubG+u1HqSx2j4q53XDolUWLnd6vpxyeCWq0rMGEcnMeoq6G/YCc3dWsv3jyDU8NGlcjR8LBAkEAqgJbp/fJSBIMLwp18iHkPARwJpA50KcuIE4ADDuJtOJFTg87APvFcskJO6GExxi9Yftfx8TX4OFd6sQuJ4rjuQJBAJzLtUW8scySLRxEDGDKJVZjzBiJlM+A7ByaaviAOBm0ByYAD9fxchfAZJj03MST0I5BW4D25Tjiovvk1EN3bpk=";

    private static final String TEST_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5l9AeFsO+48CJwKUKrkvFB9XN+KTcDJMNWoxAsBiyX9Jva+n++QdhgIER8S/vTyYCZ4MAwr66vzZvo2/QlogW+dmwpfyMjsar2yNCdyUdNFb9SbAo12qyx7GGAG4A1B+Cm5yjGyFjOMvng10WjLob4Bocw0z+n7pARx4tcqfP7wIDAQAB";

    private static Logger LOG = Logger.getLogger(App.class.getName());

    public static void main(String[] args)
    {
        JWTService service = new JWTService();
        try
        {
            String jwt = service.createJWT("varun", TEST_PRIVATE_KEY);
            LOG.info("Jwt generated: " + jwt);

            LOG.info("");
            LOG.info("=================================================");

            String userFromJwt = service.validateJWT(jwt, TEST_PUBLIC_KEY);
            LOG.info("JWT validation successful. User from JWT: " + userFromJwt);
        }
        catch (IllegalArgumentException | UnsupportedEncodingException | InvalidKeySpecException
                | NoSuchPaddingException | NoSuchAlgorithmException | JWTException e)
        {
            LOG.error("Error occurred", e);
        }

    }
}
