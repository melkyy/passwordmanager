package com.ignita.service;

import com.ignita.Main;
import com.ignita.model.PasswordMasterModel;
import com.ignita.model.PasswordModel;
import com.ignita.repository.PasswordRepository;
import org.json.JSONArray;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordService {
    PasswordRepository passwordRepository;
    EncryptionService encryptionService;
    MasterPasswordService masterPasswordService;

    public PasswordService(JSONArray passwordList){
        passwordRepository = new PasswordRepository(passwordList);
        encryptionService = new EncryptionService();
        masterPasswordService = new MasterPasswordService();
    }


    public void encryptPasswordListFile(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        System.out.println("JSON LIST::: "+ passwordRepository.getPasswordList().toString());
        encryptionService.encryptFile(password, Main.filePathDB,  passwordRepository.getPasswordList().toString());
    }


    public void list() {
        System.out.println("LISTING...");
        PasswordModel[] pm;
        pm = passwordRepository.list();
        if (pm.length == 0) {
            System.out.println("No items in list create one");
            return;
        }
        int index= 1;
        for (PasswordModel passwordModel : pm) {

            System.out.println("-----------------------");
            System.out.println("index: "+ index);
            System.out.println("Name: " + passwordModel.getName());
            System.out.println("Password: " + passwordModel.getPassword().replaceAll(".(?=.*)", "*"));
            System.out.println("-----------------------");
            index++;
        }
    }

    public void add(String password, String name) {
        if (password.isBlank()) {
            System.out.println("Password required");
            return;
        }
        if (name.isBlank()) {
            System.out.println("Name required");
        }
        passwordRepository.add(password, name);
        System.out.println("Password added");
        this.list();
    }

    public void show(int index){
        PasswordModel pm = passwordRepository.show(index - 1);
        System.out.println("-----------------------");
        System.out.println("index: "+index);
        System.out.println("Name: " + pm.getName());
        System.out.println("Password: "+ pm.getPassword());
        System.out.println("-----------------------");
    }

    public void remove(int index){
        passwordRepository.remove(index - 1);
        System.out.println("Password Removed");
    }
}
