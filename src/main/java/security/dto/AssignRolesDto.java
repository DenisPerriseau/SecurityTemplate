package security.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AssignRolesDto {

    private String email;
    private String  role;
}