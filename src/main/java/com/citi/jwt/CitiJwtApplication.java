package com.citi.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.amqp.RabbitAutoConfiguration;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestTemplate;


@EnableScheduling
@SpringBootApplication
@EnableAutoConfiguration( exclude = RabbitAutoConfiguration.class) 
@EnableAsync
@EnableDiscoveryClient
@EnableFeignClients
public class CitiJwtApplication {
		
	public static void main(String[] args) {
		SpringApplication.run(CitiJwtApplication.class, args);
	}
	
	
	@LoadBalanced
	@Bean
	RestTemplate restTemplate()
	{
		return new RestTemplate();
	}
	

}
