import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class Decryption {
    private static final String algorithm = "AES";
    //Java에서는 PKCS#5 = PKCS#7이랑 동일
    //자세한 내용은 http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html 참고.
    private static final String blockNPadding = algorithm + "/CBC/PKCS5Padding";
    private static final String password = "This is Key";
    private static final String IV = "This is Vector";

    private static IvParameterSpec ivSpec;
    private static Key keySpec;

    public static void setIvSpec(IvParameterSpec ivSpec) {
        Decryption.ivSpec = ivSpec;
    }
    public static void setKeySpec(Key keySpec) {
        Decryption.keySpec = keySpec;
    }
    public static void main(String[] args) throws Exception {
        MakeKey(password);
        MakeVector(IV);
        // Test-file "100 Sales Records" (5KB zip-file) downloaded at http://eforexcel.com/wp/downloads-18-sample-csv-files-data-sets-for-testing-sales/
        // and encrypted (100-Sales-RecordsEncrypted.enc) using the unchanged C# code
        new Decryption().decrypt(new File("C:/test/100-Sales-RecordsEncrypted.enc"), new File("C:/test/100-Sales-RecordsDecrypted.zip"));

    }
    /**
     * 32자리의 키값을 이용하여 SecretKeySpec 생성
     * @param  password                     절대 유출되서는 안되는 키 값이며, 이것으로 키스펙을 생성
     * @throws UnsupportedEncodingException 지원되지 않는 인코딩 사용시 발생
     * @throws NoSuchAlgorithmException     잘못된 알고리즘을 입력하여 키를 생성할 경우 발생
     * @throws InvalidKeySpecException      잘못된 키 스펙이 생성될 경우 발생
     */
    public static void MakeKey(String password)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
        //암호키를 생성하는 팩토리 객체 생성
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        //다이제스트를 이용하여, SHA-512로 단방향 해시 생성 (salt 생성용)
        MessageDigest digest = MessageDigest.getInstance("SHA-512");

        // C# : byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(password);
        byte[] keyBytes = password.getBytes("UTF-8");
        // C# : byte[] saltBytes = SHA512.Create().ComputeHash(keyBytes);
        byte[] saltBytes = digest.digest(keyBytes);

        // 256bit (AES256은 256bit의 키, 128bit의 블록사이즈를 가짐.)
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
        Key secretKey = factory.generateSecret(pbeKeySpec);

        // 256bit = 32byte
        byte[] key = new byte[32];
        System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
        //AES 알고리즘을 적용하여 암호화키 생성
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        setKeySpec(secret);
    }
    /**
     * 16자리 초기화벡터 입력하여 ivSpec을 생성한다.
     * @param  IV                     절대 유출되서는 안되는 키 값이며, 이것으로 키스펙을 생성
     * @throws UnsupportedEncodingException 지원되지 않는 인코딩 사용시 발생
     * @throws NoSuchAlgorithmException     잘못된 알고리즘을 입력하여 키를 생성할 경우 발생
     * @throws InvalidKeySpecException      잘못된 키 스펙이 생성될 경우 발생
     * @
     */
    public static void MakeVector(String IV)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] vectorBytes = IV.getBytes("UTF-8");
        byte[] saltBytes = digest.digest(vectorBytes);

        // 128bit
        PBEKeySpec pbeKeySpec = new PBEKeySpec(IV.toCharArray(), saltBytes, 65536, 128);
        Key secretIV = factory.generateSecret(pbeKeySpec);

        // 128bit = 16byte
        byte[] iv = new byte[16];
        System.arraycopy(secretIV.getEncoded(), 0, iv, 0, 16);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        setIvSpec(ivSpec);
    }
    /**
     * 원본 파일을 복호화해서 대상 파일을 만든다.
     * @param source 원본 파일
     * @param dest 대상 파일
     * @throws Exception
     */
    public void decrypt(File source, File dest) throws Exception {
        Cipher c = Cipher.getInstance(blockNPadding);
        c.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        fileProcessing(source, dest, c);
    }
    /**
     * 파일 복호화 처리
     * @param source 원본 파일
     * @param dest   대상 파일
     * @param c      생성된 Cipher 객체 전달
     * @throws Exception
     * @Step
     *  1. 생성한 파일의 버퍼를 읽어들임.
     *  2. Base64 인코딩된 문자열 -> Base64 디코딩 Byte[]로 변환
     *  3. Base64 디코딩 Byte[] -> Cipher.update를 사용하여 AES256 Decryption 실행
     *  4. Cipher.doFinal()로 마지막 Padding을 추가.
     */
    public void fileProcessing(File source, File dest, Cipher c) throws Exception {
        InputStream input = null;
        OutputStream output = null;

        try {
            input = new BufferedInputStream(new FileInputStream(source));
            output = new BufferedOutputStream(new FileOutputStream(dest));
            byte[] buffer = new byte[4 * (input.available() / 4)];
            int read = -1;
            while ((read = input.read(buffer)) != -1) {
                byte[] bufferEncoded = buffer;
                if (read != buffer.length) {
                    bufferEncoded = Arrays.copyOf(buffer, read); //버퍼에 읽힌 값을 bufferEncoded에 Array Copy
                }
                byte[] bufferDecoded = Base64.getDecoder().decode(bufferEncoded); //Base64 Decode
                output.write(c.update(bufferDecoded)); //AES256 Decryption
            }
            output.write(c.doFinal()); // Last Padding add
        } catch (BadPaddingException e){
            e.printStackTrace();
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                }
            }
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                }
            }
        }
    }
}
