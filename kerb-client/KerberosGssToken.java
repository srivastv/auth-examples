import java.util.Base64;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


/**
 * @author varun
 */
public class KerberosGssToken
{
    // java -Dsun.security.jgss.native=true -Dsun.security.jgss.lib=/usr/lib/64/libgss.so KerberosGssToken
    public static void main(String[] args) throws GSSException
    {
        String service = args[0];
        System.out.println(getToken(service));
    }

    private static String getToken(String service) throws GSSException
    {
        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

        GSSManager gssManager = GSSManager.getInstance();
        GSSName serverName = gssManager.createName("HTTP@" + service, GSSName.NT_HOSTBASED_SERVICE,  krb5Oid);
        GSSContext gssContext = gssManager.createContext(serverName,
            krb5Oid,
            null,
            GSSContext.DEFAULT_LIFETIME);


        byte[] gssToken = new byte[0];
        gssToken = gssContext.initSecContext(gssToken, 0, 0);

        if (gssToken != null) {

            Base64.Encoder base64 = Base64.getEncoder();
            return base64.encodeToString(gssToken);
        }
        return null;
    }
}
