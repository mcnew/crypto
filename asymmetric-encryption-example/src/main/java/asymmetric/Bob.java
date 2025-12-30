package asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Bob {

	private static final String SECRET_MESSAGE = "Hello, Alice! This is a secret message.";

	private PublicKey alicePublicKey;

	public void receiveAlicePublicKey(byte[] encodedPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
		// Reconstruct the PublicKey from the X509 encoded byte array
		X509EncodedKeySpec encodedKey = new X509EncodedKeySpec(encodedPublicKey);

		// Create a KeyFactory for RSA and generate the PublicKey
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		this.alicePublicKey = rsaKeyFactory.generatePublic(encodedKey);
	}

	public byte[] encryptMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// Create a Cipher instance for RSA decryption with PKCS1 padding
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// Initialize the cipher in ENCRYPT_MODE with the public key
		cipher.init(Cipher.ENCRYPT_MODE, alicePublicKey);

		// Convert the plaintext string to bytes using UTF-8
		byte[] plainTextBytes = SECRET_MESSAGE.getBytes(StandardCharsets.UTF_8);

		// Perform the encryption
		return cipher.doFinal(plainTextBytes);
	}

}
