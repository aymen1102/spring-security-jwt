package com.aybaroud.springsecurityjwt.security.utils;

public class JWTUtil {
    public static final String SECRET = "mySecret1234";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 1 * 60 * 1000;
    public static final long EXPIRE_REFRESH_TOKEN = 15 * 60 * 1000;
}
