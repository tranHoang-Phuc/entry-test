package com.dts.entry.identityservice.utils;

import com.dts.entry.identityservice.consts.CookieConstant;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.yaml.snakeyaml.scanner.Constant;

public class CookieUtils {
    public static void setTokenCookies(HttpServletResponse response, SignInResponse tokenResponse) {
        ResponseCookie accessCookie = ResponseCookie.from(CookieConstant.ACCESS_TOKEN, tokenResponse.accessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(tokenResponse.expiresIn())
                .sameSite("None")
                .build();
        ResponseCookie refreshCookie = ResponseCookie.from(CookieConstant.REFRESH_TOKEN, tokenResponse.refreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(tokenResponse.expiresIn())
                .sameSite("None")
                .build();


        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }

    public static void revokeTokenCookies(HttpServletResponse response) {
        ResponseCookie accessCookie = ResponseCookie.from(CookieConstant.ACCESS_TOKEN, null)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("None")
                .build();
        ResponseCookie refreshCookie = ResponseCookie.from(CookieConstant.REFRESH_TOKEN, null)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("None")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }
    public static void clearCookie(HttpServletResponse response) {
        Cookie accessToken = new Cookie("Authorization", null);
        accessToken.setMaxAge(0);
        accessToken.setPath("/");

        Cookie refreshToken = new Cookie("refresh_token", null);
        refreshToken.setMaxAge(0);
        refreshToken.setPath("/");

        response.addCookie(accessToken);
        response.addCookie(refreshToken);
    }

    public static String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(name)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}