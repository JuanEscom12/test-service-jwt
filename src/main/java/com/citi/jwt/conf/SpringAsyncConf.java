package com.citi.jwt.conf;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAsync
@Slf4j
public class SpringAsyncConf implements AsyncConfigurer {
	
	
	@Value("${app.max-pool-size}")
	private Integer maxPoolSixe;
	
	@Override
	public Executor getAsyncExecutor() {
		log.info(":: Executor conf {} ", maxPoolSixe);
		return Executors.newFixedThreadPool(maxPoolSixe);
	}
	

}
