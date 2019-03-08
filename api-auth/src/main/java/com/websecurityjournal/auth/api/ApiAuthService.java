package com.websecurityjournal.auth.api;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * Service for hmac based api authentication.
 * 
 * @author varun
 */
public class ApiAuthService
{
    private static final String HTTP = "http://";
    private static final String HTTPS = "https://";
    private static final String FORWARD_SLASH = "/";
    private static final String QUERY_MARKER = "?";
    private static final String SEPARATOR = ";";
    private static final String UTF_8 = "UTF-8";
    private static final String AMP = "&";
    private static final String EQUALS = "=";
    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private static Logger LOG = Logger.getLogger(ApiAuthService.class.getName());

    /**
     * Method to get HMAC value of the requested values for Api key authentication.
     *
     * @param secretKey
     *            SecretKey using which HMAC-SHA256 will be calculated
     * @param apiKey
     *            ApiKey for the user
     * @param uri
     *            URI client trying to access.
     * @param timeStamp
     *            Unix TimeStamp send by client
     * @param postParamsMap
     *            Map of parameters sent in the request. This should include only
     *            post parameters.
     * @param httpMethod
     *            HTTP verb i.e. GET/POST/PUT etc
     * @return Hmac
     * @throws ApiKeyException
     */
    public String getHmacHash(String secretKey, String apiKey, String uri, String timeStamp,
            Map<String, String> postParamsMap, String httpMethod) throws ApiKeyException
    {
        if (apiKey == null || secretKey == null)
        {
            throw new ApiKeyException("apiKey and secretKey cannot be null");
        }

        if (uri == null)
        {
            throw new ApiKeyException("uri cannot be null");
        }

        if (timeStamp == null || httpMethod == null || uri == null)
        {
            throw new ApiKeyException("Mandatory parameters timeStamp: " + timeStamp + " apiKey: ***" + " httpMethod: "
                    + httpMethod + " uri: " + uri + "secretKey: *** cannot be null ");
        }

        Map<String, String> sortedParamsMap = new TreeMap<>();

        // get params from query string
        Map<String, String> queryParamMap;
        queryParamMap = getQueryParamMapFromUri(uri);

        // add post params
        queryParamMap.putAll(postParamsMap);

        if (queryParamMap != null)
        {
            sortedParamsMap.putAll(queryParamMap);
        }

        // truncating the query params from uri
        int startIndex = uri.indexOf(QUERY_MARKER);
        if (startIndex != -1)
        {
            uri = uri.substring(0, startIndex);
        }

        StringBuilder dataBuilder = new StringBuilder();
        dataBuilder.append(apiKey).append(SEPARATOR).append(timeStamp).append(SEPARATOR).append(uri);
        String paramaterString = getParamString(sortedParamsMap);

        dataBuilder.append(SEPARATOR).append(httpMethod);

        if (paramaterString != null)
        {
            dataBuilder.append(SEPARATOR).append(paramaterString);
        }

        String calcluatedHmac = null;

        try
        {
            calcluatedHmac = calculateHMAC(dataBuilder.toString(), secretKey);
        }
        catch (SignatureException e)
        {
            throw new ApiKeyException(e);
        }

        return calcluatedHmac;
    }

    /**
     * Method to calculate the HMAC-SHA256 hash.
     *
     * @param data
     *            : Data to be hashed
     * @param hashKey
     *            : Key to be used for HMAC-SHA256 hash calculation
     * @return : HMAC-SHA256 hash of the data in Base64 encoded format.
     * @throws java.security.SignatureException
     */
    private String calculateHMAC(String data, String hashKey) throws java.security.SignatureException
    {
        LOG.info("Final auth string before hashing : " + data);

        String result;

        try
        {
            // get an hmac_sha256 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(hashKey.getBytes(), HMAC_SHA256_ALGORITHM);

            // get an hmac_sha256 Mac instance and initialize with signing key
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes());

            // base64-encode the hmac
            // result = Encoding.EncodeBase64(rawHmac);
            result = Base64.getEncoder().encodeToString(rawHmac);
        }
        catch (Exception e)
        {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }
        return result;
    }

    /**
     * Creates a string from the params map. This url encodes the param key and
     * value and creates a query string with parameters that is used for calculating
     * hmac.
     *
     * @param paramsMap
     * @return
     */
    private static String getParamString(Map<String, String> paramsMap)
    {
        if (paramsMap == null || paramsMap.isEmpty())
        {
            return null;
        }

        StringBuilder bldr = new StringBuilder();
        for (Entry<String, String> entry : paramsMap.entrySet())
        {
            if (bldr.length() > 0)
            {
                bldr.append(AMP);
            }

            bldr.append(entry.getKey()).append(EQUALS).append(entry.getValue());
        }
        return bldr.toString();
    }

    /**
     * Extract the uri from the url.
     * 
     * @param targetUrl
     *            Given url.
     * @return uri for the url.
     */
    public static String getUriFromUrl(String url)
    {
        if (url == null)
        {
            return null;
        }

        String uri = url;

        if (url.startsWith(HTTPS))
        {
            uri = url.substring(HTTPS.length());
        }

        else if (url.startsWith(HTTP))
        {
            uri = url.substring(HTTP.length());
        }

        if (uri != null)
        {
            int startIndex = uri.indexOf(FORWARD_SLASH);

            if (startIndex != -1)
            {
                uri = uri.substring(startIndex);
            }
            else
            {
                uri = "";
            }
        }

        if (uri == null)
        {
            uri = "";
        }

        return uri;
    }

    /**
     * Method to get the queryMap from a uri
     * 
     * @param url
     *            Given uri.
     * @return queryMap
     * @throws ApiKeyException
     */
    private static Map<String, String> getQueryParamMapFromUri(String uri) throws ApiKeyException
    {
        if (uri == null)
        {
            return null;
        }

        Map<String, String> queryParamsMap = new HashMap<>();

        String queryString = null;

        if (uri.indexOf(QUERY_MARKER) >= 0)
        {
            queryString = uri.substring(uri.indexOf(QUERY_MARKER) + 1);
            try
            {
                queryString = URLDecoder.decode(queryString, UTF_8);
            }
            catch (UnsupportedEncodingException e)
            {
                e.printStackTrace();
                throw new ApiKeyException(e);
            }
        }

        queryParamsMap = getQueryParamMapFromQueryString(queryString);

        return queryParamsMap;
    }

    /**
     * Method to get the queryMap from a queryString
     * 
     * @param queryString
     *            : query string
     * @return : queryMap
     */
    private static Map<String, String> getQueryParamMapFromQueryString(String queryString)
    {
        Map<String, String> queryParamsMap = new HashMap<>();

        if (queryString != null)
        {
            String[] params = queryString.split(AMP);
            for (String param : params)
            {
                if (param != null)
                {
                    int index = param.indexOf(EQUALS);
                    if (index == -1)
                    {
                        queryParamsMap.put(param, "");
                    }
                    else
                    {
                        String key = param.substring(0, index);
                        String value = param.substring(index + 1, param.length());
                        queryParamsMap.put(key, value);
                    }
                }
            }
        }

        return queryParamsMap;
    }
}
