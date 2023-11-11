package isp;

import fri.isp.Agent;
import fri.isp.Environment;

//import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with c (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {

    private static byte[] cipherText;
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Generate a secret key with the desired key length
        final Key Ckey = KeyGenerator.getInstance("ChaCha20").generateKey();
  
        // Create an AES key that is used by Bob and the public-space
        final Key Akey = KeyGenerator.getInstance("AES").generateKey();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                send("bob", data);

                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashedData = digest.digest(data);

                System.out.printf("HasedData Alice:  %s%n", Agent.hex(hashedData));

                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                final byte[] nonce = new byte [12];
                new SecureRandom().nextBytes(nonce);

                final Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");

                IvParameterSpec iv = new IvParameterSpec(nonce);

                encrypt.init(Cipher.ENCRYPT_MODE, Ckey,iv);
                //System.out.printf(encrypt.);

                
                final byte[] cipherText = encrypt.doFinal(hashedData);

                send("public-space",cipherText);
                send("public-space", nonce);
                
                // Use the key that you have created above.

            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {

                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice

                byte[] cipherText = receive("alice");
                byte[] nonce = receive("alice");

                System.out.printf("Encrypted Hash:  %s%n", Agent.hex(cipherText));
                IvParameterSpec iv = new IvParameterSpec(nonce);

                final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");

                decrypt.init(Cipher.DECRYPT_MODE, Ckey,iv);
                final byte[] hashedDataP = decrypt.doFinal(cipherText);

                System.out.printf("HasedData Public:  %s%n", Agent.hex(hashedDataP));

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob

                final Cipher public_space = Cipher.getInstance("AES/GCM/NoPadding");
                public_space.init(Cipher.ENCRYPT_MODE, Akey);
                final byte[] iv_p = public_space.getIV();

                final byte[] cipherText2 = public_space.doFinal(hashedDataP);

                send("bob",cipherText2);
                send("bob",iv_p);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {


                // Receive the data from Alice and compute the digest over it using SHA-256

                byte[] data = receive("alice");

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashedData_a = digest.digest(data);
                     
                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM

                byte[] ct = receive("public-space");
                byte[] iv = receive("public-space"); 
                
                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);

                bob.init(Cipher.DECRYPT_MODE, Akey, specs);
                final byte[] hashedData_p = bob.doFinal(ct);

                System.out.printf("Computed digest:  %s%n", Agent.hex(hashedData_a));
                System.out.printf("received digest:  %s%n", Agent.hex(hashedData_p));
            
                if (Arrays.equals(hashedData_a, hashedData_p)) {
                    System.out.println("data valid");
                } else {
                    System.out.println("data invalid");
                }
                   

                // Print "valid" if the byte arrays are equal, otherwise print "invalid"
                //System.out.println(areEqual ? "valid" : "invalid");
                

                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
