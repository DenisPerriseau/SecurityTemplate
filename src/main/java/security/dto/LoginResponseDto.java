package security.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponseDto {
    
    private String token;
    private long expiresIn;
    private String refreshToken;
}