package com.dts.entry.identityservice.component;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class RedisConnectionTester implements CommandLineRunner {

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Override
    public void run(String... args) {
        try {
            redisTemplate.opsForValue().set("testKey", "Redis OK!");
            String value = redisTemplate.opsForValue().get("testKey");
            log.info("✅ Redis connected: " + value);
        } catch (Exception e) {
            log.error("❌ Redis connection failed: " + e.getMessage());
        }
    }
}
