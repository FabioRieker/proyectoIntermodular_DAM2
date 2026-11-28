package com.vulnfollowup.scan;

public class ScanAlreadyRunningException extends RuntimeException {

    public ScanAlreadyRunningException() {
        super("Ya hay un análisis en curso");
    }

}
