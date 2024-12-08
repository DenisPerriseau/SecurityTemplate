package security.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import security.dto.ApiError;
import security.enums.ResponseMessage;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice  // This annotation handles global exception management within the application.
public class GlobalExceptionHandler {

    // Initialize the logger to record errors into logs.
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // Handle JWT signature errors (invalid signature)
    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ApiError> handleSignatureException(SignatureException ex) {
        // Return an error response with a specific message for the signature error, status is 403 (forbidden)
        return buildErrorResponse(ResponseMessage.ERROR_403.getMessage(), HttpStatus.FORBIDDEN, ex);
    }

    // Handle JWT expiration errors
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiError> handleExpiredJwtException(ExpiredJwtException ex) {
        // Return an error response with a specific message for the expired token, status is 401 (unauthorized)
        return buildErrorResponse(ResponseMessage.ERROR_401.getMessage(), HttpStatus.UNAUTHORIZED, ex);
    }

    // Handle authentication errors: bad credentials provided
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> handleBadCredentialsException(BadCredentialsException ex) {
        // Return an error message when the credentials are incorrect (status 401)
        return buildErrorResponse(ResponseMessage.ERROR_401.getMessage(), HttpStatus.UNAUTHORIZED, ex);
    }

    // Handle errors related to account status (e.g., account locked)
    @ExceptionHandler(AccountStatusException.class)
    public ResponseEntity<ApiError> handleAccountStatusException(AccountStatusException ex) {
        // Return an error message when the account is locked or inactive (status 403)
        return buildErrorResponse(ResponseMessage.ERROR_403.getMessage(), HttpStatus.FORBIDDEN, ex);
    }

    // Handle access denied errors to a protected resource
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDeniedException(AccessDeniedException ex) {
        // Return an error message when access is denied (status 403)
        return buildErrorResponse(ResponseMessage.ERROR_403.getMessage(), HttpStatus.FORBIDDEN, ex);
    }

    // Handle validation errors of data (e.g., field errors in a form)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationException(MethodArgumentNotValidException ex) {
        // This method handles validation errors like invalid form fields.
        logger.error("Validation error", ex);  // Log the error
        Map<String, String> errors = new HashMap<>();
        // Collect validation error details (field name and error message)
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );
        // Return a bad request response with field validation errors
        return ResponseEntity.badRequest().body(errors);
    }

    // Handle exceptions when a user already exists
    @ExceptionHandler(AuthenticationExceptions.UserAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleUserAlreadyExistsException(AuthenticationExceptions.UserAlreadyExistsException ex) {
        // Return an error message when the user already exists (status 400)
        return buildErrorResponse(ResponseMessage.ERROR_400.getMessage(), HttpStatus.BAD_REQUEST, ex);
    }

    // Handle invalid password errors
    @ExceptionHandler(AuthenticationExceptions.InvalidPasswordException.class)
    public ResponseEntity<ApiError> handleInvalidPasswordException(AuthenticationExceptions.InvalidPasswordException ex) {
        // Return an error message when the provided password is invalid (status 400)
        return buildErrorResponse(ResponseMessage.ERROR_400.getMessage(), HttpStatus.BAD_REQUEST, ex);
    }

    // Handle errors when the refresh token is invalid
    @ExceptionHandler(AuthenticationExceptions.InvalidRefreshTokenException.class)
    public ResponseEntity<ApiError> handleInvalidRefreshTokenException(AuthenticationExceptions.InvalidRefreshTokenException ex) {
        // Return an error message for an invalid refresh token (status 400)
        return buildErrorResponse(ResponseMessage.ERROR_400.getMessage(), HttpStatus.BAD_REQUEST, ex);
    }

    // Handle internal server errors or unexpected errors
    @ExceptionHandler(InternalServerErrorException.class)
    public ResponseEntity<ApiError> handleInternalServerErrorException(InternalServerErrorException ex) {
        // Return an error response for internal server errors (status 500)
        return buildErrorResponse(ResponseMessage.ERROR_500.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, ex);
    }

    // Handle general exceptions that are not explicitly handled elsewhere
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception ex) {
        // Return an error message for any unexpected error (status 500)
        return buildErrorResponse(ResponseMessage.ERROR_500.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, ex);
    }

    // Handle errors related to invalid argument passed to methods
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException ex) {
        // Return an error message when the provided arguments are invalid (status 400)
        return buildErrorResponse(ResponseMessage.ERROR_400.getMessage(), HttpStatus.BAD_REQUEST, ex);
    }

    // Handle user not found errors
    @ExceptionHandler(AuthenticationExceptions.UserNotFoundException.class)
    public ResponseEntity<ApiError> handleUserNotFoundException(AuthenticationExceptions.UserNotFoundException ex) {
        // Return an error message when the user is not found (status 404)
        return buildErrorResponse(String.format(ResponseMessage.ERROR_404.getMessage(), ex.getMessage()), HttpStatus.NOT_FOUND, ex);
    }

    // Handle invalid role errors
    @ExceptionHandler(AuthenticationExceptions.InvalidRoleException.class)
    public ResponseEntity<ApiError> handleInvalidRoleException(AuthenticationExceptions.InvalidRoleException ex) {
        // Return an error message when the role is invalid (status 400)
        return buildErrorResponse(String.format(ResponseMessage.ERROR_400.getMessage(), ex.getMessage()), HttpStatus.BAD_REQUEST, ex);
    }

    // Handle role not found errors
    @ExceptionHandler(AuthenticationExceptions.RoleNotFoundException.class)
    public ResponseEntity<ApiError> handleRoleNotFoundException(AuthenticationExceptions.RoleNotFoundException ex) {
        // Return an error message when the role is not found (status 400)
        return buildErrorResponse(ResponseMessage.ERROR_400.getMessage(), HttpStatus.BAD_REQUEST, ex);
    }

    // Utility method to build a uniform error response
    private ResponseEntity<ApiError> buildErrorResponse(String message, HttpStatus status, Exception ex) {
        logger.error(message, ex);  // Log the error message with exception details
        ApiError apiError = new ApiError(status.value(), status.getReasonPhrase(), message, null);
        // Return the error response with the status and message
        return ResponseEntity.status(status).body(apiError);
    }
}
