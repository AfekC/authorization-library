package com.example.authz.engine;

/** Which validated credentials were present on the request. */
public enum AuthType {
    USER,
    SERVICE,
    USER_AND_SERVICE
}
