# 3200_project
Honeypot: Employee Portal

Environments to run on:
  Please run this program on either Ubuntu 16.04 LTS or Mac OS X Yosemite.
  The program may run in other environments, but as been tested and developed
  in the environments named above. The one thing that you will need to run this
  program successfully, is a terminal bash shell. The code has been tested and
  run in these shells and works perfectly. Therefore the product should work
  100% in the above environments.

How to compile:
  To compile the code to run this program please use the following command:

      javac Server.java
      javac Client.java

How to run:
  To the the program please have two different shells open in the folder and
  enter the following commands:

  In the first shell:
    java Server

  In the second shell:
    java Client localhost

  once you have both running the client will ask for a username, the options
  for this are:
                alex
                bernice
                candice
                donald
                erin

  After this, it will ask for a password. The password every user is pass.
  Once you have a password, you have will have three different options prompted
  to the user. These options are:
                Status
                report
                done
  These options all do different task. The done task ends the program. The
  report task only works for our manager, in this case, would be Alex. The
  report task displays the status of all users.

  Next you have the status task, which is available to all user. The status
  option will then prompt you with three other options, these are:
                working
                off
                break
  The user can choose any of these and it will update their status.

  When something goes wrong, or a malicious task is seen it will log it to a
  log file. You can view the log, by opening the logFile.txt. This holds a log
  of everything that has gone wrong.
    (the file is standing so every time it is the file does not reset. you can
    manually clean it by deleting the contents and saving).

   A big aspect of this portal is that it uses both RSA, and AES encryption.
   This means that user has their own private key, and it is needed to log in.
   Also all communication to the server is encrypted, so anyone who may manage
   to grab the transmission will not be able to decrypt it.

    Also with each offense, they carry a point value. When they add up to 6,
    user will be disconnected and logged. The values associated with each
    offense are:
              6 points for a wrong key
              3 points per wrong username
              3 points per a wrong Password
              2 points if wrong task is clicked
              2 points for invalid command

Again every time an offense is seen, it will add and log it to the logFile.txt.
