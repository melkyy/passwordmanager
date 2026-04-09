package com.ignita.service;

import com.ignita.model.MasterModel;
import com.ignita.repository.PasswordRepository;

import java.lang.reflect.Array;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordService {
    private static final Random RANDOM = new SecureRandom();
    private static final int ITERATIONS = 50000;
    private static final int KEY_LENGTH = 256;

    private byte[] generateHash() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public MasterModel checkFile() {
        System.out.println("CHECKING MASTER FILE...");

        PasswordRepository passwordRepository = new PasswordRepository();
        MasterModel masterInfo = passwordRepository.getMasterPasswordFile();
        Scanner Scan = new Scanner(System.in);

        if(masterInfo == null){
            System.out.println("Enter new password: ");
            System.out.println("NOTICE: If you forget the password, it cannot be recovered");
            String newPassword = Scan.nextLine();

            masterInfo = passwordRepository.setMasterPasswordFile(newPassword, generateHash(), ITERATIONS, KEY_LENGTH);
            System.out.println("Password set!!");
        }
        return masterInfo;
    }

    public void enterPassword(MasterModel masterInfo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("--- WELCOME! ---");

        PasswordRepository passwordRepository = new PasswordRepository();
        Scanner Scan = new Scanner(System.in);

        System.out.println("Enter Password: ");
        String newPassword = Scan.nextLine();
        if(validatePassword(newPassword, masterInfo.getSaltByte(), masterInfo.getPasswordByte())){
            System.out.println("Correct Password");
        }else{
            System.out.println("Incorrect Password");
        }
    }

    public static boolean validatePassword (String password, byte[] salt, byte[] storedHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("VALIDATING PASSWORD...");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        return Arrays.equals(hashedPassword, storedHash);
    }
}
