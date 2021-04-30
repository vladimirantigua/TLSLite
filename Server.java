package vladimirAntigua.msd;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Server {
// variables:

    private static int port = 8080;
    private static ServerSocket serverSocket;
    //Nonce
    public static byte[] clientNonce;
    //Socket
    private static Socket socket;
    private static BigInteger Ks;
    private static BigInteger Ns;
    private static BigInteger g = new BigInteger("2");
    private static byte[] server_DHPublicKey;
    private static byte[] client_DHPublicKey;
    private static byte[] DHSharedSecret;
    // 6 session key:
    private static SecretKeySpec serverEncrypt;
    private static SecretKeySpec clientEncrypt;
    private static SecretKeySpec serverMAC;
    private static SecretKeySpec clientMAC;
    private static IvParameterSpec serverIV;
    private static IvParameterSpec clientIV;



    private static ByteArrayOutputStream history = new ByteArrayOutputStream();

    public static void handShakeWithClient() throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //receive the client nonce
        receiveNonce();

        //Server: Server Certificate, DiffieHellman public key,
        // Signed DiffieHellman public key (Sign[g^ks % N, Spriv])
        sendServerCertificate();
        sendDHPublicKey();
        sendSignedDHPublic();

        //Server received from Client: Client Certificate, DiffieHellman public key,
        // Signed DiffieHellman public key (Sign[g^kc % N, Cpriv])
        client_DHPublicKey = KeyCalculation.verifySignedDHPublicKey(socket,history);

        //server compute the shared secret here using DH
        DHSharedSecret = KeyCalculation.computeShareDHKey(client_DHPublicKey, Ks.toByteArray(),Ns.toByteArray());

        //server derive 6 session keys from the shared secret.
        makeSecretKeys();

        //send MAC to client
        MACCalculation.sendMAC(socket, serverMAC,history);

        //receive client MAC
        MACCalculation.receiveMAC(socket,clientMAC,history);
        //For this application, when we receive a certificate, we'll make sure that
        // it is signed by our CA.For this application, when we receive a certificate,
        // we'll make sure that it is signed by our CA.
        System.out.println("Server successfully completed the handshake with the client... ;)");
    }
    // implement the receiveNonce
    public static void receiveNonce() throws IOException {
        clientNonce = KeyCalculation.receiveByte(socket);
        history.writeBytes(clientNonce);

    }
    // send the server certificate:
    public static void sendServerCertificate() throws IOException, CertificateException {
        byte[] certificateByte = KeyCalculation.readCertificate("server");
        KeyCalculation.sendByte(socket, certificateByte);
        history.writeBytes(certificateByte);
    }
    public static void  sendDHPublicKey() throws IOException {
        Ks = KeyCalculation.generateDHPrivateKey();
        Ns = new BigInteger(KeyCalculation.getN(), 16);
        server_DHPublicKey = KeyCalculation.computeDHPublicKey(g,Ks,Ns).toByteArray();
        KeyCalculation.sendByte(socket, server_DHPublicKey);
        history.writeBytes(server_DHPublicKey);
    }
    public static void sendSignedDHPublic() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        PrivateKey RSA_privateKey = KeyCalculation.readPrivateKey("server");
        byte[] signedDHPublicKey = KeyCalculation.signDHPublicKey(server_DHPublicKey, RSA_privateKey);
        //to send it out
        KeyCalculation.sendByte(socket,signedDHPublicKey);
        //to store it:
        history.writeBytes(signedDHPublicKey);
    }

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
        public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, InvalidKeyException, SignatureException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException {
            // write your code here
            //password
            // (stdin)= 66b21afbdc973dc6951659817bdbe0d7422efa53aed8bdb201fb25fe60fbb5cf
            // (stdin)= 66b21afbdc973dc6951659817bdbe0d7422efa53aed8bdb201fb25fe60fbb5cf

            serverSocket = new ServerSocket(port);
            System.out.println("Server starts a connection with the client.... :) ");

            socket = serverSocket.accept();
            System.out.println("Server successfully connected with the client.... :) ");

            //handshake with client: Helper functions
            handShakeWithClient();
            System.out.println("Server successfully start handshake with the client.... :) ");

            sendFile("test.txt");
            System.out.println("Server  successfully send test.txt from the client.... :) ");
            receiveACK();
        }
    public static void sendFile(String fileName) throws IOException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        FileInputStream  fileInputStream = new FileInputStream(fileName);
        byte[] fileBytes = fileInputStream.readAllBytes();
        MACCalculation.sendEncryptedData(socket, fileBytes, serverEncrypt, serverIV);

    }
    public static void receiveACK() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] ACKBytes = MACCalculation.receivedEncryptedData(socket, clientEncrypt, clientIV);
        String ACKMessage = new String(ACKBytes);
        if(ACKMessage.equals("File received")){
            System.out.println("Server successfully receive an ACK from the client");
        }
    }
}













