package security.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Define a constant for the description key
    private static final String DESCRIPTION_KEY = "description";
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetail;

        // Log the stack trace using the logger
        logger.error("Exception occurred: ", exception);

        if (exception instanceof BadCredentialsException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
            errorDetail.setProperty(DESCRIPTION_KEY, "The username or password is incorrect");
            return errorDetail;
        }

        if (exception instanceof AccountStatusException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
            errorDetail.setProperty(DESCRIPTION_KEY, "The account is locked");
            return errorDetail;
        }

        if (exception instanceof AccessDeniedException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
            errorDetail.setProperty(DESCRIPTION_KEY, "You are not authorized to access this resource");
            return errorDetail;
        }

        if (exception instanceof SignatureException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
            errorDetail.setProperty(DESCRIPTION_KEY, "The JWT signature is invalid");
            return errorDetail;
        }

        if (exception instanceof ExpiredJwtException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
            errorDetail.setProperty(DESCRIPTION_KEY, "The JWT token has expired");
            return errorDetail;
        }

        // Directly assign errorDetail if no exception type matches
        errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
        errorDetail.setProperty(DESCRIPTION_KEY, "Unknown internal server error.");

        return errorDetail;
    }
}
