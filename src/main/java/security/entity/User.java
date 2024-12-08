package security.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import security.enums.Role;

import java.util.*;

@Getter
@Setter

@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false,  unique = true)
    private Integer id;

    // Setter pour fullName
    @Setter
    @Column(unique = true)
    private String fullName;

    // Setter pour email
    @Setter
    @Column(unique = true, length = 100, nullable = false)
    private String email;

    @Getter
    @Column(nullable = false)
    private String password;

    @CreationTimestamp
    @Column(updatable = false, name = "created_at")
    private Date createdAt;

    // Indicateurs pour l'état du compte
    @Column(nullable = false)
    private boolean accountExpired = false;  // Par défaut, le compte n'est pas expiré

    @Column(nullable = false)
    private boolean accountLocked = false;  // Par défaut, le compte n'est pas verrouillé

    @Column(nullable = false)
    private boolean credentialsExpired = false;  // Par défaut, les informations d'identification ne sont pas expirées

    @Column(nullable = false)
    private boolean enabled = true;  // Par défaut, le compte est activé

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Date updatedAt;

    // Les rôles sont stockés dans une table de jointure
    // Initialisation du Set à une collection vide pour éviter NullPointerException
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>(); // Initialisation ici pour éviter NullPointerException

    // Implémentation de la méthode de l'interface UserDetails
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Convertir les rôles en authorities
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))  // Associer chaque rôle à une authority
                .toList();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

}


