
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class NimcPwdAlgorithm {

    //	private static final String CIPHER_TRANSFORMATION = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    private static final String CIPHER_TRANSFORMATION = "RSA";

    public static String getNimcEncrpytedPassword(String password) {

//		byte[] sha256 = DigestUtils.sha256(password);
        String sha256 = DigestUtils.sha256Hex(password);

//		BigInteger bigInteger = new BigInteger(sha256);
//
//		String key = bigInteger.toString(16);
//
        PublicKey publicKey = getPublicKey();

        return encrypt(sha256, publicKey);
    }

    public static String encrypt(String val, PublicKey publicKey) {

        Cipher encryptionCipher;
        try {
            encryptionCipher = getEncryptionCipher(publicKey);
            return encrypt(val, encryptionCipher);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot get encrypt ", e);
        }
    }

    public static String encrypt(String plainText, Cipher ecipher) throws IllegalBlockSizeException, BadPaddingException {
        byte[] scrambled = ecipher.doFinal(plainText.getBytes(Charset.forName("UTF-8")));
        return Base64.getEncoder().encodeToString(scrambled);
    }

    private static Cipher getEncryptionCipher(PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher;
    }

    public static PublicKey getPublicKey() {

        // Hardcode the RSA key
        String modulusString = "9965644084057417656330538552189694824948559788786878830575584" +
                "44367368137357168893841560814041088567854117014580575728077016098213" +
                "77138238971482595936817351313377639458003034637351529602924774615106" +
                "03187506573682837654908296256987136765436092899557443263849530849288" +
                "7000005021125506027838956077501182295786099";

//		String exponentString = "18bc01730656bde47476f7cfbd3d8f9e15ede9c389814672dc161e349b08627fc885fe9d2442ae92f0214c7e97cf0b9a9fc876df4f53517ab63d710f997b2779";
        String publicExponentString = 	"113621440243785421499955306133900099987164309503876199371900" +
                "61108597569919490562171044287644188919530245192244355535426664573745" +
                "43274095096393339893842623857299495786240442076109488216273558766935" +
                "70108394899808569346703874513552461157771585312437842555207875241788" +
                "331401870311503661882350734256428011446552231";

//		String publicExponentString = "65537";

        System.out.println("modulusString length : "+modulusString.length());
        System.out.println("publicExponentString length : "+publicExponentString.length());

        // Load the key into BigIntegers
        BigInteger modulus = new BigInteger(modulusString);
//		BigInteger exponent = new BigInteger(exponentString, 16);
        BigInteger pubExponent = new BigInteger(publicExponentString);

        // Create private and public key specs
//		RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, exponent);
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);

        // Create a key factory
        KeyFactory factory;
        try {
//			factory = KeyFactory.getInstance("RSA");
            factory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown Algorithm. Should never happen", e);
        }

        // Create the RSA private and public keys
//		PrivateKey priv = factory.generatePrivate(privateSpec);
        PublicKey pub;

        try {
            pub = factory.generatePublic(publicSpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid Key Spec. Should never happen", e);
        }

        return pub;
    }

    private static PublicKey createPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String publicExponent = "113621440243785421499955306133900099987164309503876199371900" +
                "61108597569919490562171044287644188919530245192244355535426664573745" +
                "43274095096393339893842623857299495786240442076109488216273558766935" +
                "70108394899808569346703874513552461157771585312437842555207875241788" +
                "331401870311503661882350734256428011446552231";

        String publicModulus = "9965644084057417656330538552189694824948559788786878830575584" +
                "44367368137357168893841560814041088567854117014580575728077016098213" +
                "77138238971482595936817351313377639458003034637351529602924774615106" +
                "03187506573682837654908296256987136765436092899557443263849530849288" +
                "7000005021125506027838956077501182295786099";

        BigInteger modulus = new BigInteger(publicModulus);
        BigInteger exponent = new BigInteger(publicExponent);
        RSAPublicKeySpec keySpeck = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpeck);
    }


    private static String getSha256(String str) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown Algorithm. Should never happen", e);
        }
        byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
        return null;
    }

    public static void main(String[] args) throws Exception {
        test2();
    }

    public static void test2() throws Exception {
        String nimcEncrpytedPassword = getNimcEncrpytedPassword("Ebuka2019!");
        System.out.println("nimcEncrpytedPassword : -"+nimcEncrpytedPassword+"-");
    }

    public static void test() {

        String password = "BUSKy@0987";

        String sha256 = DigestUtils.sha256Hex(password);


        System.out.println("sha256 : \n"+sha256);

        BigInteger bigInteger;

        bigInteger = new BigInteger(sha256, 16);

        System.out.println(bigInteger);
        System.out.println(bigInteger.toString(16));

        System.out.println("==============================");

        byte[] sha256byteArray = DigestUtils.sha256(password);

        System.out.println("sha256byteArray length : "+sha256byteArray.length);

        bigInteger = new BigInteger(sha256byteArray);

        System.out.println(bigInteger);
        System.out.println(bigInteger.toString(16));

    }


}
