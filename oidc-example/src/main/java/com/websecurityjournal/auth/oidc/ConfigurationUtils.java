package com.websecurityjournal.auth.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Class for populating property maps from File.
 *
 * @author varun
 *
 */
public class ConfigurationUtils
{
    private static final Logger LOG = Logger.getLogger(ConfigurationUtils.class);

    private static final String FILE_NAME = "config.json";
    private static final String SAML_CERTIFICATE = "x509Certificate";

    private static ConfigurationUtils fileConfigProvider;

    private Set<String> samlCertificates = new HashSet<>();

    /**
     * Method to create singleton instance of this class.
     *
     * @return ConfigurationUtils
     */
    public static synchronized ConfigurationUtils getInstance()
    {
        if (fileConfigProvider == null)
        {
            fileConfigProvider = new ConfigurationUtils();
        }

        return fileConfigProvider;
    }

    private ConfigurationUtils()
    {
    }

    /**
     * Read the configuration from config file in json format if it has been
     * modified since last read.
     *
     */
    public void refreshProperties()
    {
        try
        {

            String propertyFile = FILE_NAME;

            LOG.info("Loading property file : " + propertyFile);

            final InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(propertyFile);
            final Reader reader = new InputStreamReader(inputStream);

            final JSONObject allAttributes = (JSONObject) new JSONParser().parse(reader);

            @SuppressWarnings("unchecked")
            final String certificate = (String) allAttributes.get(SAML_CERTIFICATE);

            if (!StringUtils.isEmpty(certificate))
            {
                samlCertificates.add(certificate);
            }

            LOG.info("Saml certificate  : " + certificate);

        }
        catch (IOException | ParseException e)
        {

            LOG.error("Error in parsing config file", e);
        }
    }

    public Set<String> getX509CertificatesForIssuer(String issuer)
    {
        refreshProperties();
        return samlCertificates;
    }

    public String getIdpUrl()
    {
        return "";
    }

    public String getClientId()
    {
        return "";
    }

    public String getRedirectUrl()
    {
        return "http://localhost:8080/callback";
    }

}
