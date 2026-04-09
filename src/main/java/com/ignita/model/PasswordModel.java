package com.ignita.model;

public class PasswordModel {
    public String id;
    public String password;
    public String name;

    public String getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getName(){
        return name;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setId(String id) {
        this.id = id;
    }

}
