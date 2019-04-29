package com.websecurityjournal.auth.oidc;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * This is the action for initiating login request to Idp.
 *
 * @author varun
 */
public class LoginAction extends HttpServlet
{
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = Logger.getLogger(LoginAction.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        String flow = request.getParameter("flow");
        // implicit flow. implicit flow is not for backend based applications
        // https://<idp_domain>/oidc/auth?
        // client_id=<client_id>&redirect_uri=<callback_url>&response_type=id_token&scope=openid&nonce=123

        // auth flow
        // https://<idp_domain>/oidc/auth?
        // client_id=<client_id>&redirect_uri=<callback_url>&response_type=code&scope=openid&nonce=123
        String url = getIdpUrl(flow);

        try
        {
            response.sendRedirect(url);
            return;
        }
        catch (Exception e)
        {
            LOG.error(e);
        }
    }

    private String getIdpUrl(String flow)
    {
        String responseType = "code";
        String state = "code-1234";
        String nonce = "12345"; // session specific random value
        StringBuilder bldr = new StringBuilder();
        ConfigurationUtils config = ConfigurationUtils.getInstance();
        config.getIdpUrl();
        bldr.append(config.getIdpUrl());
        bldr.append("?client_id=");
        bldr.append(config.getClientId());
        bldr.append("&redirect_uri=");
        bldr.append(config.getRedirectUrl());
        bldr.append("&response_type=");
        bldr.append(responseType);
        bldr.append("&scope=openid");
        bldr.append("&state=");
        bldr.append(state);
        bldr.append("&nonce=");
        bldr.append(nonce);

        return bldr.toString();

    }

}
