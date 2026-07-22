package com.meerkatgramv2auth.global.error.custom;

public class InvalidPostCreateException extends RuntimeException {
    public InvalidPostCreateException(String message) {
        super(message);
    }
}
