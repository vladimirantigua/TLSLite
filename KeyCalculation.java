package vladimirAntigua.msd;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Random;

public class KeyCalculation {
    //implement DiffieHellman Algo:
    public static BigInteger computeDHPublicKey(BigInteger g, BigInteger K, BigInteger N){
        return g.modPow(K, N); //g^k mod n  to get public key

    }

    // to get private key: to compute the public key
    public static BigInteger generateDHPrivateKey(){
        // random #
        Random random = new Random();
        // to generate 2048 to be used to compute the public key:
        BigInteger K = new BigInteger(2048, random);

        return K;

    }
//
    public static String getN(){
        String string  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

        return string;
    }

    public static void sendInt(Socket socket, int num) throws IOException {

        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
        dataOutputStream.writeInt(num);

    }

    public static void sendByte(Socket socket, byte[] toBeSent) throws IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
        dataOutputStream.writeInt(toBeSent.length);
        dataOutputStream.write(toBeSent);// send byte read from socket
    }

    public static int receiveInt(Socket socket)  throws IOException {

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream()); // reading the socket

        return dataInputStream.readInt();
    }

    public static byte[] receiveByte(Socket socket) throws IOException {

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream()); // reading from the socket
        int len = dataInputStream.readInt();

        if(len > 0){
            byte[] message = new byte[len]; // byte array to store the message we read from the socket
            dataInputStream.readFully(message, 0, message.length); // read from 0 to the length of the array
            return message;
        }
        return null;
    }

    public static byte[] readCertificate(String string) throws IOException, CertificateException {

        String fileName;
        if(string.equals("client")){
            fileName =    "CASignedClientCertificate.pem";
        }
        else {
            fileName = "CASignedServerCertificate.pem";
        }
        FileInputStream fileInputStream = new FileInputStream(fileName);

        return fileInputStream.readAllBytes();
    }
    //http://tutorials.jenkov.com/java-cryptography/signature.html
    public static byte[] signDHPublicKey(byte[] DHPublicKey, PrivateKey RSA_privateKey) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {

        Signature signature = Signature.getInstance("SHA256WithRSA"); // get the instance of signature
        SecureRandom secureRandom = new SecureRandom();
        signature.initSign(RSA_privateKey, secureRandom);
        signature.update(DHPublicKey);

        return signature.sign();
    }

    public static PrivateKey readPrivateKey(String string) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String fileName = string + "PrivateKey.der";
        FileInputStream fileInputStream = new FileInputStream(fileName);
        byte[] keyBytes = fileInputStream.readAllBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes); // to help produce the private key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // to help produce the private key

        return keyFactory.generatePrivate(spec);
    }

    public static PublicKey getRSAPublicKey(byte[] certificateBytes) throws CertificateException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificateBytes);
        Certificate certificate = certificateFactory.generateCertificate(byteArrayInputStream);

        return certificate.getPublicKey(); // to read the public key with the certificate
    }

    public static boolean verify(byte[] signature_toBeVerify, byte[] DHPublicKey_toBeVerify, PublicKey RSAPublickey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(RSAPublickey);
        signature.update(DHPublicKey_toBeVerify);

        return signature.verify(signature_toBeVerify);
    }

    public static byte[] verifySignedDHPublicKey(Socket socket, ByteArrayOutputStream historyByte) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] certificate = KeyCalculation.receiveByte(socket);
        historyByte.writeBytes(certificate);
        PublicKey RSAPublicKey = KeyCalculation.getRSAPublicKey(certificate);
        byte[] DHPublicKey = KeyCalculation.receiveByte(socket);
        historyByte.writeBytes(DHPublicKey);
        byte[] signedDHPublicKey = KeyCalculation.receiveByte(socket);
        historyByte.writeBytes(signedDHPublicKey);

        boolean verify = KeyCalculation.verify(signedDHPublicKey, DHPublicKey, RSAPublicKey);
        if(!verify){// verify = false close the communication stop the socket
            socket.close();
            System.exit(1);
        }

        return DHPublicKey;
    }
    public static byte[] computeShareDHKey(byte[] t, byte[] k, byte[] n){
        BigInteger T = new BigInteger(t);
        BigInteger K = new BigInteger(k);
        BigInteger N = new BigInteger(n);

        return T.modPow(K, N).toByteArray();
    }

}
