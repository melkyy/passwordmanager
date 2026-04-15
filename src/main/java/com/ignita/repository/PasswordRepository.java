package com.ignita.repository;

import com.ignita.Main;
import com.ignita.model.PasswordModel;
import org.json.JSONArray;
import org.json.JSONObject;

public class PasswordRepository {
    private JSONArray passwordList = null;

    public PasswordRepository(JSONArray passwordList){
        this.passwordList = passwordList;
    }

    public JSONArray getPasswordList() {
        return passwordList;
    }


    public PasswordModel[] list() {
        if(this.passwordList != null){
            PasswordModel[] pmArray = new PasswordModel[this.passwordList.length()];
            for (int i = 0; i < this.passwordList.length(); i++){
                JSONObject obj = this.passwordList.getJSONObject(i);
                PasswordModel pm = new PasswordModel();
                pm.setName(obj.getString("name"));
                pm.setPassword(obj.getString("password"));
                pmArray[i] = pm;
            }
            return pmArray;
        }else{
            return null;
        }
    }

    public PasswordModel show(int index) {
        if(this.passwordList != null){
            PasswordModel pm = new PasswordModel();
                JSONObject obj = this.passwordList.getJSONObject(index);
                if(obj != null){
                    pm.setName(obj.getString("name"));
                    pm.setPassword(obj.getString("password"));
                }
            return pm;
        }else{
            return null;
        }
    }

    public void add(String password, String name) {
        JSONObject newPassword =  new JSONObject();
        newPassword.put("password", password);
        newPassword.put("name", name);
        this.passwordList.put(newPassword);
    }

    public void remove(int index) {
        this.passwordList.remove(index);
    }
}
