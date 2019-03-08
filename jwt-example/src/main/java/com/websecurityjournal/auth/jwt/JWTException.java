/**
 * 
 */
package com.websecurityjournal.auth.jwt;

/**
 * @author varun
 *
 */
public class JWTException extends Exception
{

    private static final long serialVersionUID = 3753977132305883889L;

    public JWTException()
    {
        super();
    }

    public JWTException(String message)
    {
        super(message);
    }

}
