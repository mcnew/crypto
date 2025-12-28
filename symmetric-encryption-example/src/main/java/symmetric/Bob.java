package symmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Bob {

	private static final String SECRET_MESSAGE = "Hello, Alice! This is a secret message.";

	private SecretKey aliceSecretKey;

	private GCMParameterSpec parameterSpec;

	public void receiveAliceSecretKey(byte[] encodedSecretKey, byte[] iv) {
		// Reconstruct the SecretKey from the raw byte array
		this.aliceSecretKey = new SecretKeySpec(encodedSecretKey, 0, encodedSecretKey.length, "AES");

		// Reconstruct the GCMParameterSpec using the received IV
		this.parameterSpec = new GCMParameterSpec(128, iv);
	}

	public byte[] encryptMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Create a Cipher instance for AES encryption in GCM mode with NoPadding
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

		// Initialize the cipher in ENCRYPT_MODE with the received secret key and IV
		cipher.init(Cipher.ENCRYPT_MODE, aliceSecretKey, parameterSpec);

		// Convert the plaintext string to bytes using UTF-8
		byte[] plainTextBytes = SECRET_MESSAGE.getBytes(StandardCharsets.UTF_8);

		// Encrypt the message using the received secret key and IV
		return cipher.doFinal(plainTextBytes);
	}

}
