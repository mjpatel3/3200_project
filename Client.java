/*
*@author: Manthan Patel ((mpatel99)
*Client.java
*purpose of this class is to be the client for users to be, and connect to server
*after it connects it tells server how to update user listening
*clients has chipers to encode messages
*/
import java.io.*;
import java.util.Scanner;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;

/** Client supporting simple interactionw with the server. */

public class Client {

  public static String request = "";

  public static boolean checkStatusOptions(String input){
      input = input.toLowerCase();
      if(input.equals("working")){
        request = "status Working";
        return true;
      }else if( input.equals("off")){
        request = "status off";
        return true;
      }else if(input.equals("break")){
        request = "status break";
        return true;
      }


    return false;
  }

  public static void statusMenu(){
    System.out.println("Please choose your status accordingly: ");
    System.out.println("   working");
    System.out.println("   off");
    System.out.println("   break");

  }

  public static void mainMenu(){
    System.out.println("");
    System.out.println("Welcome to your Employee Portal");
    System.out.println("please choose one of the flowing commands");
    System.out.println("    status");
    System.out.println("    report");
    System.out.println("    done" );
  }
  public static void main( String[] args ) {
    // Complain if we don't get the right number of arguments.
    if ( args.length != 1 ) {
      System.out.println( "Usage: Client <host>" );
      System.exit( -1 );
    }

    try {
      // Try to create a socket connection to the server.
      Socket sock = new Socket( args[ 0 ], Server.PORT_NUMBER );

      // Get formatted input/output streams for talking with the server.
      DataInputStream input = new DataInputStream( sock.getInputStream() );
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );

      // Get a username from the user and send it to the server.
      int go = 0;
      int count = 0;
      String name;
      String password;
      Scanner scanner;

      do{
        scanner = new Scanner( System.in );
        System.out.print( "Username: " );
        name = scanner.nextLine();
        output.writeUTF( name );
        output.flush();

        go = input.readInt();
        // System.out.println("Go is " + go);
        count++;
      } while(go != 1 && count < 2);

      if( go == 0){
        sock.close();
        System.exit(-1);
      }

      count = 0;
      do{
          go = 0;
        scanner = new Scanner( System.in );
        System.out.print( "Password: " );
        password = scanner.nextLine();
        output.writeUTF( password );
        output.flush();

        go = input.readInt();
        // System.out.println("Go is " + go);

        count++;
      } while(go != 1 && count < 2);

      if( go == 0){
        sock.close();
        System.exit(-1);
      }

      // Try to read the user's private key.
      Scanner keyScanner = new Scanner( new File( name + ".txt" ) );
      String hexKey = keyScanner.nextLine();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );
      keyScanner.close();

      // Make a key specification based on this key.
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( rawKey );

      // Get an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      PrivateKey privateKey = keyFactory.generatePrivate( privKeySpec );

      // Make a cipher object that will encrypt using this key.
      Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
      RSAEncrypter.init( Cipher.ENCRYPT_MODE, privateKey );

      // Make another cipher object that will decrypt using this key.
      Cipher RSADecrypter = Cipher.getInstance( "RSA" );
      RSADecrypter.init( Cipher.DECRYPT_MODE, privateKey );

      // Get the challenge string (really a byte array) from the server.
      byte[] challenge = Server.getMessage( input );


      // Encrypt the challenge with our private key and send it back.
      // ...
      byte[] encryptChallenge = RSAEncrypter.doFinal(challenge);

//sends message to server
      Server.putMessage(output, encryptChallenge);

      // Get the symmetric key from the server and make AES
      // encrypt/decrypt objects for it.
      // ...

//creates key for ase from sessionkey provided by server
      SecretKey aes_key = new SecretKeySpec(RSADecrypter.doFinal(Server.getMessage(input)), "AES");

//cretaes Ciphers for AES encoding

      Cipher AESEncrypter = Cipher.getInstance("AES/ECB/PKCS5Padding");
      AESEncrypter.init( Cipher.ENCRYPT_MODE, aes_key );

      Cipher AESDecrypter = Cipher.getInstance("AES/ECB/PKCS5Padding");
      AESDecrypter.init( Cipher.DECRYPT_MODE, aes_key );


      // Read commands from the user and print server responses.
      // String request = "";
      mainMenu();

      System.out.print( "cmd> " );
      while ( scanner.hasNextLine() && ! ( request = scanner.next() ).equals( "done" ) ) {
        request = request.toLowerCase();

        if(request.equals("status")){
          statusMenu();
          request = scanner.next();
          if(!checkStatusOptions(request)){
             request = "invd";
          }
        }



        Server.putMessage( output, AESEncrypter.doFinal(request.getBytes() ));

        // Read and print the response.
        String response = new String( AESDecrypter.doFinal(Server.getMessage( input )) );
        System.out.print( response );
        mainMenu();
        System.out.print( "cmd> " );
      }

      // Send the done command to the server.
      Server.putMessage( output, AESEncrypter.doFinal(request.getBytes() ) );



      // We are done communicating with the server.
      sock.close();
    } catch( IOException e ){
      System.err.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    }
  }
}
