package com.dts.entry.identityservice.utils;

import com.dts.entry.identityservice.consts.CookieConstants;
import com.dts.entry.identityservice.viewmodel.response.SignInResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    private static int refreshableDuration;
    private static int validDuration;

    @Value("${jwt.refreshable-duration}")
    public void setRefreshableDuration(int duration) {
        CookieUtils.refreshableDuration = duration;
    }

    @Value("${jwt.valid-duration}")
    public void setValidDuration(int duration) {
        CookieUtils.validDuration = duration;
    }

    public static void setTokenCookies(HttpServletResponse response, SignInResponse tokenResponse) {
        ResponseCookie accessCookie = ResponseCookie.from(CookieConstants.ACCESS_TOKEN, tokenResponse.accessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(validDuration)
                .sameSite("None")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from(CookieConstants.REFRESH_TOKEN, tokenResponse.refreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshableDuration)
                .sameSite("None")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }

    public static void revokeTokenCookies(HttpServletResponse response) {
        ResponseCookie accessCookie = ResponseCookie.from(CookieConstants.ACCESS_TOKEN, "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("None")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from(CookieConstants.REFRESH_TOKEN, "")
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
