package asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Alice {

	private PrivateKey privateKey;

	private PublicKey publicKey;

	public void createKeyPair() throws NoSuchAlgorithmException {
		// Generate RSA key pair
		KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = rsaKeyPairGenerator.generateKeyPair();

		// Store the private and public keys
		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
	}

	public byte[] getPublicKey() {
		// Return X509 encoded public key
		return this.publicKey.getEncoded();
	}

	public String decryptBomMessage(byte[] encryptedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Create a Cipher instance for RSA decryption with PKCS1 padding
		var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// Initialize the cipher in DECRYPT_MODE with the private key
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

		// Perform the decryption
		return new String(cipher.doFinal(encryptedMessage), StandardCharsets.UTF_8);
	}

}
