# Password manager
A lightweight Java console application implementing secure file handling, cryptographic, and persistent data storage.

# Overview
This console application manages a secure password vault by generating two primary files:
- ### Master configuration
   A properties file where the master password and salt are generated the content are hashed in case of unauthorized access.
- ### Password list
  file where your stored credentials are located their contents are encrypted and can only be decrypted using the master password


# Motivation
This project is build to learn about crypto and hashing as well as learn about file handling
and improve my knowledge in Java language.


# Quick start
Download latest `.jar` file located in [releases](https://github.com/melkyy/passwordmanager/releases)
open terminal, navigate to the same directory and run the application using:
<br>
`java -jar passswordmanager.jar`

Take into account that when you set a master password it will generate a directory located in `C://passwordManagerDataJAVA`
or root in directory
