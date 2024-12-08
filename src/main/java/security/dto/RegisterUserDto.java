package security.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterUserDto {

    private String fullName;
    private String email;
    private String password;
}