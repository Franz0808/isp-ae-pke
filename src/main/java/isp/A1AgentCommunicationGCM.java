package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key sharedKey = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                // System.out.printf("MSG: %s%n", text);
                // System.out.printf("PT:  %s%n", Agent.hex(pt));

                // encrypt
                for (int i = 0; i < 10; i++) {

                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, sharedKey);

                    final byte[] ct = alice.doFinal(pt);
                    // System.out.printf("CT:  %s%n", Agent.hex(ct));

                    // send IV
                    final byte[] iv = alice.getIV();
                    System.out.printf("IV:  %s%n", Agent.hex(iv));

                    send("bob", ct);
                    send("bob", iv);

                    byte[] ct2 = receive("bob");
                    byte[] iv2 = receive("bob"); 
                    
                    //final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv2);

                    alice.init(Cipher.DECRYPT_MODE, sharedKey, specs);
                    final byte[] pt3 = alice.doFinal(ct2);

                    // System.out.printf("PT:  %s%n", Agent.hex(pt2));
                    System.out.printf("MSG from Bob: %s%n", new String(pt3, StandardCharsets.UTF_8));



            }
        }});

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                final String message1 = "I love you too";
                final byte[] pt1 = message1.getBytes();

                for (int i = 0; i < 10; i++) {

                    byte[] ct = receive("alice");
                    byte[] iv = receive("alice"); 

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv);

                    bob.init(Cipher.DECRYPT_MODE, sharedKey, specs);
                    final byte[] pt2 = bob.doFinal(ct);

                    // System.out.printf("PT:  %s%n", Agent.hex(pt2));
                    System.out.printf("MSG from Alice: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    //answer alice
                    bob.init(Cipher.ENCRYPT_MODE, sharedKey);

                    final byte[] ct1 = bob.doFinal(pt1);
                    // System.out.printf("CT:  %s%n", Agent.hex(ct));
                    // send IV
                    final byte[] iv1 = bob.getIV();
                    System.out.printf("IV:  %s%n", Agent.hex(iv1));
                    // System.out.printf("IV:  %s%n", Agent.hex(iv));
                    send("alice", ct1);
                    send("alice", iv1);
            }
        }});

        env.connect("alice", "bob");
        env.start();
    }
}
