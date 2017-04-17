/**
*@author: Manthan Patel (mjpatel3)
*server.java
*purpose of this class is to be the server for clients to connect to and
*send and receive messges to encrypt and decrypt
*/
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.Random;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.GeneralSecurityException;
import javax.xml.bind.DatatypeConverter;

/** A server that keeps up with a public key for every user, along with a current
    value for every user (whether or not they are connected.) */
public class Server {
  /** Port number used by the server */
  public static final int PORT_NUMBER = 26126;

  /** Record for an individual user. */
  private static class UserRec {
    // Name of this user.
    String name;

    // This user's public key.
    PublicKey publicKey;

    // Current status of this user, defaults to unknown.
    String status = "unknown";
  }

  /** List of all the user records. */
  private ArrayList< UserRec > userList = new ArrayList< UserRec >();

  SecretKey key;

  /** Read all user records. */
  private void readUserRecs() throws IOException, GeneralSecurityException {
    Scanner input = new Scanner( new File( "passwd.txt" ) );
    // While there are more usernames.
    while ( input.hasNext() ) {
      // Create a record for the next user.
      UserRec rec = new UserRec();
      rec.name = input.next();

      // Get the key as a string of hex digits and turn it into a byte array.
      String hexKey = input.nextLine().trim();
      byte[] rawKey = DatatypeConverter.parseHexBinary( hexKey );

      // Make a key specification based on this key.
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( rawKey );

      // Make an RSA key based on this specification
      KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
      rec.publicKey = keyFactory.generatePublic( pubKeySpec );


      //make an AES key


      // Add this user to the list of all users.
      userList.add( rec );
    }
  }

  /** Utility function to read a length then a byte array from the
      given stream.  TCP doesn't respect message boundaraies, but this
      is essientially a technique for marking the start and end of
      each message in the byte stream.  This can also be used by the
      client. */
  public static byte[] getMessage( DataInputStream input ) throws IOException {
    int len = input.readInt();
    byte[] msg = new byte [ len ];
    input.readFully( msg );
    return msg;
  }

  /** Function analogous to the previous one, for sending messages. */
  public static void putMessage( DataOutputStream output, byte[] msg ) throws IOException {
    // Write the length of the given message, followed by its contents.
    output.writeInt( msg.length );
    output.write( msg, 0, msg.length );
    output.flush();
  }

  /** Function to handle interaction with a client.  Really, this should be
      run in a thread. */
  public void handleClient( Socket sock ) {
    try {
      // Get formatted input/output streams for this thread.  These can read and write
      // strings, arrays of bytes, ints, lots of things.
      DataOutputStream output = new DataOutputStream( sock.getOutputStream() );
      DataInputStream input = new DataInputStream( sock.getInputStream() );

      // Get the username.
      String username = input.readUTF();

      // Make a random sequence of bytes to use as a challenge string.
      Random rand = new Random();
      byte[] challenge = new byte [ 16 ];
      rand.nextBytes( challenge );

      // Make a session key for communiating over AES.  We use it later, if the
      // client successfully authenticates.
      byte[] sessionKey = new byte [ 16 ];
      rand.nextBytes( sessionKey );

      // Find this user.  We don't need to synchronize here, sinc the set of users never
      // changes.
      UserRec rec = null;
      for ( int i = 0; rec == null && i < userList.size(); i++ )
        if ( userList.get( i ).name.equals( username ) )
          rec = userList.get( i );

      // Did we find a record for this user?
      if ( rec != null ) {
        // Make sure the client encrypted the challenge properly.
        Cipher RSADecrypter = Cipher.getInstance( "RSA" );
        RSADecrypter.init( Cipher.DECRYPT_MODE, rec.publicKey );

        Cipher RSAEncrypter = Cipher.getInstance( "RSA" );
        RSAEncrypter.init( Cipher.ENCRYPT_MODE, rec.publicKey );

        // Send the client the challenge.
        putMessage( output, challenge );

        // Get back the client's encrypted challenge.
        // ...
// gets encryptedChallenge messaeg and decrypt
      byte [] encryptedChallenge = getMessage( input );
      byte[] decryptedChallenge = RSADecrypter.doFinal( encryptedChallenge );


        // Make sure the client properly encrypted the challenge.
        // ...
        // Send the client our session key.
        byte[] encryptedKey = RSAEncrypter.doFinal( sessionKey );
        putMessage(output, encryptedKey);
        // ...

        // Make AES encrypter and decrypter ciphers.
        // ... makes SecretKey
        SecretKey aes_key = new SecretKeySpec(sessionKey, "AES");
//creates cipher for encrypting and decrypting
        Cipher AESEncrypter = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AESEncrypter.init( Cipher.ENCRYPT_MODE, aes_key );

        Cipher AESDecrypter = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AESDecrypter.init( Cipher.DECRYPT_MODE, aes_key );


        // Get the first client command and make a scanner to extract its fields.
        String request = new String( AESDecrypter.doFinal(getMessage( input )) );
        Scanner requestScanner = new Scanner( request );

        // Parse out the first word and see what it is.
        String cmd = requestScanner.next();
        while ( ! cmd.equals( "done" ) ) {
          StringBuilder reply = new StringBuilder();
// if status command
          if(cmd.equals("set") || requestScanner.hasNext()){
            reply.append( rec.status + " -> " );

            String status = requestScanner.nextLine().trim();
            rec.status = status;
            reply.append( status + "\n" );//


// if report command
          } else if(cmd.equals("report")){
            for(int i = 0; i < userList.size(); i++){
              reply.append(userList.get(i).name + ": " + userList.get(i).status + "\n");
            }
            // if command is invalid
          } else{
            reply.append("invalid command! " + "\n");
          }



          // For now, just reply with a copy of the command.

          // Send the reply back to our client.
          putMessage( output, AESEncrypter.doFinal(reply.toString().getBytes()) );

          // Get the next command.
          request = new String( AESDecrypter.doFinal(getMessage( input )) );

          requestScanner = new Scanner( request );
          cmd = requestScanner.next();
        }
      }
    } catch ( IOException e ) {
      System.out.println( "IO Error: " + e );
    } catch( GeneralSecurityException e ){
      System.err.println( "Encryption error: " + e );
    } finally {
      try {
        // Close the socket on the way out.
        sock.close();
      } catch ( Exception e ) {
      }
    }
  }

  private class Worker implements Runnable{
    Thread worker = null;
    Socket worker_sock = null;

    public Worker(Socket sock){
      worker = new Thread(this);
      worker_sock = sock;

      worker.start();

    }

    public void run(){
      handleClient(worker_sock);
    }

  }

  /** Esentially, the main method for our server. */
  private void run( String[] args ) {
    ServerSocket serverSocket = null;

    // One-time setup.
    try {
      // Read records for all the users.
      readUserRecs();

      // Open a socket for listening.
      serverSocket = new ServerSocket( PORT_NUMBER );
    } catch( Exception e ){
      System.err.println( "Can't initialize server: " + e );
      System.exit( -1 );
    }

    // Keep trying to accept new connections and serve them.
    while( true ){
      try {
        // Try to get a new client connection.
        Socket sock = serverSocket.accept();



        // Handle interaction with this client.
        new Worker( sock );
      } catch( IOException e ){
        System.err.println( "Failure accepting client " + e );
      }
    }
  }

  public static void main( String[] args ) {
    // Make a server object, so we can have non-static fields.
    Server server = new Server();
    server.run( args );
  }
}
