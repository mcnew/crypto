package symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Alice {

	private SecretKey secretKey;

	private GCMParameterSpec parameterSpec;

	public void createSecretKey() throws NoSuchAlgorithmException {

		// Create a KeyGenerator for AES algorithm
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		// Initialize the key size to 256 bits
		keyGenerator.init(256);

		// Generate an AES secret key
		this.secretKey = keyGenerator.generateKey();

		// Generate a random 12-byte IV for GCM mode
		byte[] iv = new byte[12];
		new SecureRandom().nextBytes(iv);
		this.parameterSpec = new GCMParameterSpec(128, iv);
	}

	public byte[] getSecretKey() {
		// Return the raw byte array of the secret key
		return this.secretKey.getEncoded();
	}

	public byte[] getIv() {
		return this.parameterSpec.getIV();
	}

	public String decryptBobMessage(byte[] encryptedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Create a Cipher instance for AES decryption in GCM mode with NoPadding
		var cipher = Cipher.getInstance("AES/GCM/NoPadding");

		// Initialize the cipher in DECRYPT_MODE with the secret key and IV
		cipher.init(Cipher.DECRYPT_MODE, this.secretKey, this.parameterSpec);

		// Perform the decryption
		return new String(cipher.doFinal(encryptedMessage), java.nio.charset.StandardCharsets.UTF_8);
	}

}
