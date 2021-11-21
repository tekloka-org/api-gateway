package org.tekloka.api.gateway.util;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class ResponseUtil {

	private final Logger logger = LoggerFactory.getLogger(ResponseUtil.class);
	private final ObjectMapper objectMapper;
	
	public ResponseUtil(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}
	
	public  ResponseEntity<Object> generateResponse(Map<String, Object> dataMap, String responseCode){
		var restResponse = new RestResponse(responseCode, dataMap);
		var jsonResponse = "{}";
		try {
			jsonResponse = objectMapper.writeValueAsString(restResponse);
		} catch (JsonProcessingException e) {			
			logger.error("Not able to serialize java value to a String. value: {} - {}", restResponse, e.getMessage());
		}
		return ResponseEntity.status(HttpStatus.OK).body(jsonResponse);				
	}
	
	public  String generatePlainResponse(Map<String, Object> dataMap, String responseCode){
		var restResponse = new RestResponse(responseCode, dataMap);
		var jsonResponse = "{}";
		try {
			jsonResponse = objectMapper.writeValueAsString(restResponse);
		} catch (JsonProcessingException e) {			
			logger.error("Not able to serialize java value to a String. value: {} - {}", restResponse, e.getMessage());
		}
		return jsonResponse;
	}

	
	
}