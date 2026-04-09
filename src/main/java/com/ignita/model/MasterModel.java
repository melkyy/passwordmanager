package com.ignita.model;

public class MasterModel {
    public byte[] passwordByte;
    public byte[] saltByte;

    public byte[] getPasswordByte() {
        return passwordByte;

    }

    public byte[] getSaltByte() {
        return saltByte;
    }

    public void setPasswordByte(byte[] passwordByte) {
        this.passwordByte = passwordByte;
    }

    public void setSaltByte(byte[] saltByte) {
        this.saltByte = saltByte;
    }
}
