package com.ignita;

import com.ignita.model.PasswordMasterModel;
import com.ignita.service.MasterPasswordService;
import com.ignita.service.PasswordService;
import org.json.JSONArray;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static final int ITERATIONS = 50000;
    public static final int KEY_LENGTH = 256;
    public static String mainDirectory = "C:\\passwordManagerDataJAVA";
    public static final String filePathDB = mainDirectory+"\\db.txt";
    public static final String filePathConfig = mainDirectory+"\\config.properties";

    public static void main(String[] args) {
        try {
            Path currentPath = Paths.get("").toAbsolutePath();
            Path root = currentPath.getRoot();
            Main.mainDirectory = root+"\\passwordManagerDataJAVA";
            MasterPasswordService masterPasswordService = new MasterPasswordService();
            PasswordMasterModel masterInfo;
            Scanner Scan = new Scanner(System.in);
            System.out.println("Checking directory...");
            masterPasswordService.createDirectory();
            System.out.println("Directory located at: "+ mainDirectory);
            System.out.println("Checking config file...");
            if(!masterPasswordService.masterFileExist()){
                System.out.println("File not found...");
                System.out.println("Enter a new password: ");
                System.out.println("NOTICE: If you forget the password, it cannot be recovered");
                String newPassword = Scan.nextLine();
                System.out.println("File created at: "+filePathConfig);
                masterInfo = masterPasswordService.setMasterPasswordFile(newPassword, Main.ITERATIONS, Main.KEY_LENGTH);
                System.out.println("Password set!!");
            }else{
                masterInfo = masterPasswordService.getMasterPasswordFile();
            }
            System.out.println("Enter Password: ");
            String masterPassword = Scan.nextLine();
            if (masterPassword.isEmpty()) {
                return;
            }
            if (masterPasswordService.validatePassword(masterPassword, masterInfo.getSaltByte(), masterInfo.getPasswordByte())) {
                System.out.println("----- Correct Password ------");
            } else {
                System.out.println("----- Incorrect Password ------");
                return;
            }

            String jsonString = masterPasswordService.generateFile(masterPassword);
            JSONArray passwordList = masterPasswordService.convertJSONArray(jsonString);
            PasswordService passwordService = new PasswordService(passwordList);

            String option = "";
            while (!option.equals("0")) {
                System.out.println("1 - add password");
                System.out.println("2- list password");
                System.out.println("3- show password");
                System.out.println("4- remove password");
                System.out.println("0 - exit");

                Scanner s = new Scanner(System.in);
                option = s.nextLine();
                if (option.equals("1")) {
                    System.out.println("enter a name");
                    String nameAdd = Scan.nextLine();
                    System.out.println("enter a password");
                    String passWordAdd = Scan.nextLine();
                    passwordService.add(passWordAdd, nameAdd);
                    System.out.println("ENCRYPTING...");
                    passwordService.encryptPasswordListFile(masterPassword);
                    System.out.println("The file saved successfully");
                }
                if (option.equals("2")) {
                    passwordService.list();
                }
                if (option.equals("3")) {
                    System.out.println("enter a item number");
                    String index = Scan.nextLine();
                    passwordService.show(Integer.parseInt(index));
                }
                if (option.equals("4")) {
                    System.out.println("enter a list of element by number");
                    String index = Scan.nextLine();
                    passwordService.remove(Integer.parseInt(index));
                    System.out.println("ENCRYPTING...");
                    passwordService.encryptPasswordListFile(masterPassword);
                    System.out.println("The file was saved correctly");
                }
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println("An error has occurred");
        }

    }
}