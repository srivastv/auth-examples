
package com.websecurityjournal.auth.oidc;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * This action gets the id_token using the auth code.
 */
public class CallBackAction extends HttpServlet
{
    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger(CallBackAction.class);

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {

        String code = request.getParameter("code");
        String idToken = getIdTokenFromBackend(code);

        LOG.info("ID TOKEN: " + idToken);
    }

    private String getIdTokenFromBackend(String code) throws IOException
    {
        // url -XPOST "https://<idp_domain>/oidc/token"
        // -H "Authorization: Basic <base6coded(clientId:clientSecret)>"
        // -H "Content-Type: application/x-www-form-urlencoded"
        // -d
        // "grant_type=authorization_code&code=<>&redirect_uri=http://localhost:8080/callback"

        String url = "";
        URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

        // add request header
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        String clientId = "";
        String clientKey = "";
        String userCredentials = clientId + ":" + clientKey;
        String basicAuth = "Basic " + new String(Base64.getEncoder().encodeToString(userCredentials.getBytes()));
        con.setRequestProperty("Authorization", basicAuth);

        con.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:27.0) Gecko/20100101 Firefox/27.0.2 Waterfox/27.0");

        String params = "grant_type=authorization_code&code=" + code + "&redirect_uri=http://localhost:8080/callback";

        // Send post request
        con.setDoOutput(true);
        DataOutputStream wr = new DataOutputStream(con.getOutputStream());
        wr.writeBytes(params);
        wr.flush();
        wr.close();

        int responseCode = con.getResponseCode();

        BufferedReader in = null;
        if (responseCode == 200)
        {
            in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        }
        else
        {
            in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
        }
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null)
        {
            response.append(inputLine);
        }
        in.close();

        LOG.info("Response : " + response.toString());

        return "dummyToken";
    }
}
