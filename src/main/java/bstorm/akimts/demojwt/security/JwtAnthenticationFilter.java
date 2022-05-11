package bstorm.akimts.demojwt.security;

import bstorm.akimts.demojwt.config.JwtProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JwtAnthenticationFilter extends OncePerRequestFilter {

    private final JwtProperties properties;

    public JwtAnthenticationFilter(JwtProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization").replace(properties.getPrefix(), "");

        if( token != null ){

            try {
                DecodedJWT jwt = JWT.require(Algorithm.HMAC512(properties.getSecret()))
                        .build()
                        .verify(token);

                // le token ne doit pas être expiré
                if( jwt.getExpiresAt() != null && jwt.getExpiresAt().after(new Date()) ){
                    Authentication auth = new UsernamePasswordAuthenticationToken(
                            jwt.getSubject(),
                            "",
                            jwt.getClaim("roles").asList(String.class).stream()
                                    .map( SimpleGrantedAuthority::new )
                                    .toList()
                    );

                    SecurityContextHolder.getContext()
                            .setAuthentication(auth);
                }
            }
            catch (JWTVerificationException ignored){}

            filterChain.doFilter(request, response);
        }
    }
}
