
package com.websecurityjournal.auth.saml;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.onelogin.saml2.Auth;

/**
 * This action validates the SAML response.
 */
public class SSOAction extends HttpServlet
{
    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger(SSOAction.class);

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        try
        {
            Auth auth = new Auth(request, response);
            auth.processResponse();

            if (!auth.isAuthenticated())
            {
                LOG.error("Not authenticated");
                return;
            }
            List<String> errors = auth.getErrors();
            if (!errors.isEmpty())
            {
                LOG.error("Error occured: " + errors);
                request.setAttribute("message", "Error occurred in SAML auth");
                request.getRequestDispatcher("/response.jsp").forward(request, response);
            }
            else
            {
                String nameId = auth.getNameId();
                LOG.info("NAME ID OBTAINED : " + nameId);

                String message = "SAML sucessful for user: " + nameId;
                request.setAttribute("message", message);
                request.getRequestDispatcher("/response.jsp").forward(request, response);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        // validation :
        //
        // 1. Get the saml issuer from the SAML response
        // 2. Get the SAML validation certificate for the issuer from the configuration
        // 3. Validate the SAML response using the certificates
        // 4. If validations are successful, get the email from the SAML response.
        // 5. Use 'inResponseTo' attribute in SAML response to identify whether its Idp
        // initiated or SP initiated access
    }
}
