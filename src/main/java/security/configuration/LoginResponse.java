package security.configuration;

public class LoginResponse {
    private String token;

    private long expiresIn;

    // Getter pour le champ 'token'
    public String getToken() {
        return token;
    }

    // Setter pour le champ 'token'
    public void setToken(String token) {
        this.token = token;
    }

    // Getter pour le champ 'expiresIn'
    public long getExpiresIn() {
        return expiresIn;
    }

    // Setter pour le champ 'expiresIn'
    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }
}