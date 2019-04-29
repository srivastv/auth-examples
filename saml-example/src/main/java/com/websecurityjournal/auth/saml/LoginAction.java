package com.websecurityjournal.auth.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;

import org.apache.log4j.Logger;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;

/**
 * This is the action for verifying federation setting for a customer. This
 * action is invoked to test the identity provider setting without modifying the
 * current setup.
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
        try
        {
            redirectToIdP(request, response);
        }
        catch (Exception e)
        {
            LOG.error(e);
        }
    }

    /**
     * Redirects the request to identity provider site.
     *
     * @param request
     *            Http request object
     * @param response
     *            Http response object
     * @throws IOException
     *             If some error happens.
     * @throws XMLStreamException
     *             If some error happens
     * @throws Error
     * @throws SettingsException
     */
    public static void redirectToIdP(HttpServletRequest request, HttpServletResponse response)
            throws IOException, XMLStreamException, ServletException, SettingsException, Error
    {
        Auth authRequest = new Auth("onelogin.saml.properties", request, response);
        authRequest.login();

        return;
    }
}
