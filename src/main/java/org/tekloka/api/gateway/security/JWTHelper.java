package org.tekloka.api.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTHelper {
	
	@Value("${jwt.secret.key}") 
	private String jwtSecretKey;

	private final Logger logger = LoggerFactory.getLogger(GlobalAuthFilter.class);

	public Claims decodeToken(String authToken){
		Claims claims = null;
		if (authToken != null) {
			claims = Jwts.parser().setSigningKey(jwtSecretKey.getBytes()).parseClaimsJws(authToken)
					.getBody();
		}else {
			logger.info("authTken is null");
		}
		return claims;
	}

}
