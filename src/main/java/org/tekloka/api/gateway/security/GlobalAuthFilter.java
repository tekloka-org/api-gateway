package org.tekloka.api.gateway.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.tekloka.api.gateway.costants.DataConstants;
import org.tekloka.api.gateway.costants.RestServiceConstants;
import org.tekloka.api.gateway.util.ResponseUtil;

import reactor.core.publisher.Mono;

@Component
@Order(-1)
public class GlobalAuthFilter implements GlobalFilter {

	private final JWTHelper jwtHelper;
	private final ResponseUtil responseUtil;
	private final Logger logger = LoggerFactory.getLogger(GlobalAuthFilter.class);

	public GlobalAuthFilter(JWTHelper jwtHelper, ResponseUtil responseUtil) {
		this.jwtHelper = jwtHelper;
		this.responseUtil = responseUtil;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

		ServerHttpRequest request = exchange.getRequest();

		final List<String> apiEndpoints = List.of("/public/", "/file/");

		Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
				.noneMatch(uri -> r.getURI().getPath().contains(uri));

		if (isApiSecured.test(request)) {
			String authToken = request.getHeaders().getFirst(DataConstants.X_AUTH_TOKEN);
			if (null != authToken) {
				var claims = jwtHelper.decodeToken(authToken);
				if (null != claims) {
					var loggedInUserId = "";
					if (null != claims.get(DataConstants.LOGGED_IN_USER_ID)) {
						loggedInUserId = String.valueOf(claims.get(DataConstants.LOGGED_IN_USER_ID));
					}
					return chain.filter(exchange.mutate().request(exchange.getRequest().mutate()
							.header(DataConstants.LOGGED_IN_USER_ID, loggedInUserId).build()).build());
				}else {
					logger.error("jwt claims is null");
				}
			}else {
				logger.error("X-AUTH-TOKEN is null");
			}
			Map<String, Object> dataMap = new HashMap<>();
			String response = responseUtil.generatePlainResponse(dataMap,
					RestServiceConstants.JWT_TOKEN_VALIDATION_FAILED);
			return exchange.getResponse()
					.writeWith(Mono.just(new DefaultDataBufferFactory().wrap(response.getBytes())));
		}
		return chain.filter(exchange);
	}

}
