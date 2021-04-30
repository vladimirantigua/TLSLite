

package vladimirAntigua.msd;

        import javax.crypto.*;
        import javax.crypto.spec.IvParameterSpec;
        import javax.crypto.spec.SecretKeySpec;
        import java.io.ByteArrayOutputStream;
        import java.io.IOException;
        import java.net.Socket;
        import java.nio.charset.StandardCharsets;
        import java.security.InvalidAlgorithmParameterException;
        import java.security.InvalidKeyException;
        import java.security.NoSuchAlgorithmException;
        import java.util.Arrays;

public class MACCalculation {

    public static byte[] HMAC(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac SHA256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        SHA256_HMAC.init(keySpec);
        byte[] MACBytes = SHA256_HMAC.doFinal(data);

        return MACBytes;
    }
    public static byte[] add(String tag){
        byte[] res = new byte[tag.length() + 1];
        byte[] originalBytes = tag.getBytes();
        System.arraycopy(originalBytes,0,res,0,originalBytes.length);
        res[tag.length()] = (byte) 1;

        return res;
    }
    public static byte[] hdkfExpand(byte[] key, String tag) throws InvalidKeyException, NoSuchAlgorithmException {

        byte[] okm = HMAC(key, add(tag));
        return Arrays.copyOfRange(okm,0,16);
    }
    public static void sendMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream outputStream) throws InvalidKeyException, NoSuchAlgorithmException, IOException {

        byte[] HMAC = MACCalculation.HMAC(MACKey.getEncoded(),outputStream.toByteArray());
        KeyCalculation.sendByte(socket, HMAC);
        outputStream.writeBytes(HMAC);
    }
    public static void receiveMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream outputStream) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        byte[] HMAC_received = KeyCalculation.receiveByte(socket);
        byte[] HMAC = MACCalculation.HMAC(MACKey.getEncoded(), outputStream.toByteArray());
        if(!MACCalculation.helperEquals(HMAC,HMAC_received)){
            socket.close();
            System.exit(1);
        }
        outputStream.writeBytes(HMAC_received);
    }
    //checking weather two byte arrays are equals
    public static boolean helperEquals(byte[] a, byte[] b){
        if(a.length != b.length){
            return false;
        }
        for(int i = 0; i < a.length; i ++){
            if (a[i] != b[i]){
                return false;

            }
        }
        return true;
    }
    public static byte[] encrypt(byte[] message, SecretKeySpec key, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key,IV);
        return cipher.doFinal(message);
    }
    public static byte[] decrypt(byte[] encryptData,SecretKeySpec key, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,key,IV);

        return cipher.doFinal(encryptData);
    }
    // to combine byte arrays into one byte array:
    public static byte[] concatenate(byte[] a, byte[] b) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.writeBytes(a);
        outputStream.writeBytes(b);

        return outputStream.toByteArray();
    }
    public static void sendEncryptedData(Socket socket, byte[] toBeSent, SecretKeySpec key, IvParameterSpec IV) throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        int numOfChunks = (int) Math.ceil(toBeSent.length / 1000.0);
        KeyCalculation.sendInt(socket, numOfChunks);

        for(int i = 0; i < numOfChunks; i ++){
            byte[] messageByte = Arrays.copyOfRange(toBeSent, i * 1000,(i+1)*1000);
            byte[] HMAC = MACCalculation.HMAC(key.getEncoded(), messageByte);
            byte[] concatenatedByte = MACCalculation.concatenate(messageByte,HMAC);
            byte[] encryptedByte = MACCalculation.encrypt(concatenatedByte, key, IV);
            KeyCalculation.sendByte(socket,encryptedByte);
        }
    }
    public static byte[] receivedEncryptedData(Socket socket, SecretKeySpec key, IvParameterSpec IV) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int numOfChunks = KeyCalculation.receiveInt(socket);

        for(int i = 0; i < numOfChunks; i++){
            byte[] encryptedData = KeyCalculation.receiveByte(socket);
            byte[] original = MACCalculation.decrypt(encryptedData, key, IV);
            byte[] message = new byte[original.length - 32];
            byte[] HMAC_received = new byte[32];
            System.arraycopy(original, 0,message,0,original.length - 32);
            System.arraycopy(original,original.length -32, HMAC_received, 0, 32);
            byte[] HMAC = MACCalculation.HMAC(key.getEncoded(), message);

            if(!MACCalculation.helperEquals(HMAC,HMAC_received)){
                socket.close();
                System.exit(1);
            }
            outputStream.writeBytes(message);
        }
        return outputStream.toByteArray();
    }
}

