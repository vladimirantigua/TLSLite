package vladimirAntigua.msd;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class Client {
    //variables:
    public static byte[] clientNonce;
    private static Socket socket;
    private static ByteArrayOutputStream history = new ByteArrayOutputStream();
    public static byte[] server_DHPublicKey;
    private static BigInteger K;
    private static BigInteger N;
    private static BigInteger g = new BigInteger("2");
    private static byte[] client_DHPublicKey;
    private static byte[]  DHSharedSecret;
    private static SecretKeySpec serverEncrypt;
    private static SecretKeySpec clientEncrypt;
    private static SecretKeySpec serverMAC;
    private static SecretKeySpec clientMAC;
    private static IvParameterSpec serverIV;
    private static IvParameterSpec clientIV;

    //
    public static void handShakeWithServer() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        //Client: Nonce1 (32 bytes from a SecureRandom object)
        sendClientNonce();
        System.out.println("Client send Nonce1.... :) ");

        //Client to receive from Server: Server Certificate, DiffieHellman public key,
        // Signed DiffieHellman public key (Sign[g^ks % N, Spriv])
        server_DHPublicKey = KeyCalculation.verifySignedDHPublicKey(socket, history);
        System.out.println("Client to receive from Server server_DHPublicKey .... :) ");

        //Client send to Server: Client Certificate, DiffieHellman public key,
        // Signed DiffieHellman public key (Sign[g^kc % N, Cpriv])
        sendClientCertificate();
        System.out.println("Client send certificate.... :) ");
        sendDHPublicKey();
        System.out.println("Client send DHPK.... :) ");
        sendSignedDHPublic();
        System.out.println("Client send signedDHPK.... :) ");

        //Client compute the shared secret here using DH:
        DHSharedSecret = KeyCalculation.computeShareDHKey(server_DHPublicKey, K.toByteArray(), N.toByteArray());
        System.out.println("Client computed shared secret.... :) ");

        ////client derive 6 session keys from the shared secret.
        // 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF (below)
        makeSecretKeys();
        System.out.println("Client generate 6 session keys.... :) ");

        //Client to Receive MAC from Server
        MACCalculation.receiveMAC(socket, serverMAC, history);
        System.out.println("Client receive MAC.... :) ");

        //client send the MAC to server:
        MACCalculation.sendMAC(socket, clientMAC, history);
        System.out.println("Client SEND MAC.... :) ");

        System.out.println("Client successfully completed the handshake with the server...");
    }

    private static byte[] getClientNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        return nonce;
    }

    private static void sendClientNonce() throws IOException {
        clientNonce = getClientNonce();
        KeyCalculation.sendByte(socket, clientNonce);
        history.writeBytes(clientNonce);

    }

    public static void sendClientCertificate() throws IOException, CertificateException {
        byte[] certificateBytes = KeyCalculation.readCertificate("client");
        KeyCalculation.sendByte(socket, certificateBytes);
        history.writeBytes(certificateBytes);

    }
    public static void sendDHPublicKey() throws IOException {
        K = KeyCalculation.generateDHPrivateKey();
        N = new BigInteger(KeyCalculation.getN(),16);
        client_DHPublicKey = KeyCalculation.computeDHPublicKey(g,K,N).toByteArray();
        KeyCalculation.sendByte(socket,client_DHPublicKey);
        history.writeBytes(client_DHPublicKey);
    }
    public  static void  sendSignedDHPublic() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        PrivateKey RSA_privateKey = KeyCalculation.readPrivateKey("client");
        byte[] signedDHPublicKey = KeyCalculation.signDHPublicKey(client_DHPublicKey,RSA_privateKey);
        KeyCalculation.sendByte(socket, signedDHPublicKey);
        history.writeBytes(signedDHPublicKey);
    }
    //6 Key generation: HKDF
    public static void makeSecretKeys() throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] prk = MACCalculation.HMAC(clientNonce, DHSharedSecret);
        serverEncrypt = new SecretKeySpec(MACCalculation.hdkfExpand(prk,"server encrypt"),"AES");
        clientEncrypt = new SecretKeySpec(MACCalculation.hdkfExpand(serverEncrypt.getEncoded(),"client encrypt"),"AES");
        serverMAC = new SecretKeySpec(MACCalculation.hdkfExpand(clientEncrypt.getEncoded(), "server MAC"), "SHA256");
        clientMAC = new SecretKeySpec(MACCalculation.hdkfExpand(serverMAC.getEncoded(), "client MAC"), "SHA256");
        serverIV = new IvParameterSpec(MACCalculation.hdkfExpand(clientMAC.getEncoded(), "server IV"));
        clientIV = new IvParameterSpec(MACCalculation.hdkfExpand(serverIV.getIV(),"client IV"));

    }

// Runnable:
        public static void main(String[] args) throws IOException, InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
            // write your code here
            //password
            // (stdin)= 66b21afbdc973dc6951659817bdbe0d7422efa53aed8bdb201fb25fe60fbb5cf
            // (stdin)= 66b21afbdc973dc6951659817bdbe0d7422efa53aed8bdb201fb25fe60fbb5cf

            // connecting to port 8080:
            socket = new Socket("127.0.0.1",8080);
            System.out.println("Client successfully connected with the Server.... :) ");

            handShakeWithServer();
            System.out.println("Client successfully start handshake with the server.... :) ");

            receive_File("test_received.txt");
            System.out.println("Client successfully receive test_received.txt from the Server.... :) ");
            //send the ACK
            sendACK();

        }
        // implement receive_File and send_ACK
    public static void receive_File(String fileName) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        // reading from the file:
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        byte[] bytes = MACCalculation.receivedEncryptedData(socket, serverEncrypt, serverIV);
        fileOutputStream.write(bytes);
    }
    public static void sendACK() throws IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] ACK = "File received".getBytes();
        MACCalculation.sendEncryptedData(socket, ACK, clientEncrypt, clientIV);

    }
}
