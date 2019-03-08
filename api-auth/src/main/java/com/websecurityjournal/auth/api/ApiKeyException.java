package com.websecurityjournal.auth.api;

/**
 * Exception class for API auth related functionality.
 * 
 * @author varun
 */
public class ApiKeyException extends Exception
{
    private static final long serialVersionUID = 747688698073062111L;

    /**
     * Construct the exception with empty message.
     */
    public ApiKeyException()
    {
        super();
    }

    /**
     * Construct the exception using the given message.
     *
     * @param message
     *            String exception.
     */
    public ApiKeyException(final String message)
    {
        super(message);
    }

    /**
     * CTOR.
     *
     * @param th
     *            Depicts cause for this Exception.
     */
    public ApiKeyException(Throwable th)
    {
        super(th);
    }
}
