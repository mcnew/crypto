package kem;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.BiFunction;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KEM;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Bob {

	private static final String SECRET_MESSAGE = "Hello, Alice! This is a secret message.";

	private PublicKey alicePublicKey;

	private SecretKey secretKey;

	private GCMParameterSpec parameterSpec;

	public byte[] receiveAlicePublicKeyAndGenerateEncapsulation(byte[] alicePublicKey,
			BiFunction<String, byte[], SecretKey> keyDerivation)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		// Reconstruct the PublicKey from the X509 encoded byte array
		KeyFactory keyFactory = KeyFactory.getInstance("X25519");
		X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(alicePublicKey);
		this.alicePublicKey = keyFactory.generatePublic(encodedKeySpec);

		// Create a KEM instance for DHKEM and generate encapsulation
		KEM kem = KEM.getInstance("DHKEM");
		KEM.Encapsulator encapsulator = kem.newEncapsulator(this.alicePublicKey);
		KEM.Encapsulated result = encapsulator.encapsulate();

		// Derive the shared secret key using the provided key derivation function
		byte[] sharedSecret = result.key().getEncoded();
		this.secretKey = keyDerivation.apply("AES", sharedSecret);

		// Generate a random 12-byte IV for GCM mode
		byte[] iv = new byte[12];
		new SecureRandom().nextBytes(iv);
		this.parameterSpec = new GCMParameterSpec(128, iv);

		// Return the encapsulation to be sent back to Alice
		return result.encapsulation();
	}

	public byte[] getIv() {
		return this.parameterSpec.getIV();
	}

	public byte[] encryptMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Create a Cipher instance for AES encryption in GCM mode with NoPadding
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

		// Initialize the cipher in ENCRYPT_MODE with the received secret key and IV
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		// Convert the plaintext string to bytes using UTF-8
		byte[] plainTextBytes = SECRET_MESSAGE.getBytes(StandardCharsets.UTF_8);

		// Encrypt the message using the received secret key and IV
		return cipher.doFinal(plainTextBytes);
	}

}
