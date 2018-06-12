package com.yang.encryptsample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Component;

@SpringBootApplication
@ComponentScan({"com.yang.encryptsample.controller"})
public class EncryptSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(EncryptSampleApplication.class, args);
	}
}
