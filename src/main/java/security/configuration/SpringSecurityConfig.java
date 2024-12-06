package security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;



@Configuration
public class SpringSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                // Désactiver la protection CSRF (Cross-Site Request Forgery).
                // La protection CSRF est souvent désactivée dans les applications RESTful ou API stateless
                // car elles n'utilisent pas de sessions côté serveur, et la CSRF repose sur les cookies de session.
                .csrf(csrf -> csrf.disable())

                // Configurer la gestion des sessions en mode stateless (sans état).
                // SessionCreationPolicy.STATELESS indique que l'application ne doit pas conserver d'état de session côté serveur.
                // Cela convient pour les API RESTful où chaque requête est indépendante et contient toutes les informations nécessaires à l'authentification.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configurer l'autorisation des requêtes HTTP.
                // Ici, toute requête HTTP (anyRequest) doit être authentifiée, c'est-à-dire que l'utilisateur doit être identifié pour accéder à l'application.
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())

                // Configurer l'authentification HTTP Basic avec les paramètres par défaut.
                // HTTP Basic encode les identifiants dans l'en-tête de la requête.
                // C'est simple à utiliser, mais souvent combiné avec HTTPS pour sécuriser la communication.
                .httpBasic(Customizer.withDefaults())
                .build();
    }
    /**
     * Créer un utilisateur avec un rôle USER.
     * @return un objet UserDetailsService
     */
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder().username("user").password(passwordEncoder().encode("password")).roles("USER")
                .build();
        // Retourne une instance de InMemoryUserDetailsManager.
        // Cela signifie que les utilisateurs sont stockés en mémoire (non persistant), ce qui est utile pour les tests ou les applications simples.
        return new InMemoryUserDetailsManager(user);
    }

    // Déclare un bean de type BCryptPasswordEncoder.
    // Ce bean sera utilisé pour encoder (hachage) les mots de passe de manière sécurisée.
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}