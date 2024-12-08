package security.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ApiError {
    private int statusCode;
    private String statusMessage;
    private String message;
    private Object details;

    public ApiError(int statusCode, String statusMessage, String message, Object details) {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
        this.message = message;
        this.details = details;
    }
}
