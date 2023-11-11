package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                
                final String message = "Hello Bob, I am using RSA, Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                //System.out.println("Message: " + message);
                //System.out.println("PT: " + Agent.hex(pt));

                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = rsaEnc.doFinal(pt);

                //System.out.println("Cipher: " + Agent.hex(ct));

                send("bob",ct);

        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.

        }});

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                byte[] ct = receive("alice");
                //System.out.println("Cipher attived: " + Agent.hex(ct));

                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(ct);

                //System.out.println("PT in hex: " + Agent.hex(decryptedText));
                final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                System.out.println("Message: " + message2);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
