package kem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.BiFunction;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.DecapsulateException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KEM;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Alice {

	private PrivateKey privateKey;

	private PublicKey publicKey;

	private SecretKey bobSecretKey;

	private GCMParameterSpec parameterSpec;

	public void generateKeyPair() throws NoSuchAlgorithmException {
		// Generate X25519 key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Store the private and public keys
		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
	}

	public byte[] getPublicKey() {
		// Return the encoded public key
		return this.publicKey.getEncoded();
	}

	public void receiveBobEncapsulationAndIv(byte[] bobEncapsulation, byte[] iv,
			BiFunction<String, byte[], SecretKey> keyDerivation)
			throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException {
		// Create a KEM instance for DHKEM
		KEM kem = KEM.getInstance("DHKEM");
		KEM.Decapsulator decapsulator = kem.newDecapsulator(this.privateKey);

		// Decapsulate to obtain the shared secret key
		SecretKey sharedSecretKey = decapsulator.decapsulate(bobEncapsulation);
		byte[] sharedSecret = sharedSecretKey.getEncoded();

		// Derive the secret key to communicate with Bob using the provided key
		// derivation function
		this.bobSecretKey = keyDerivation.apply("AES", sharedSecret);
		// Reconstruct the GCMParameterSpec using the received IV
		this.parameterSpec = new GCMParameterSpec(128, iv);
	}

	public String decryptBobMessage(byte[] encryptedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// Create a Cipher instance for AES decryption in GCM mode with NoPadding
		var cipher = Cipher.getInstance("AES/GCM/NoPadding");

		// Initialize the cipher in DECRYPT_MODE with the secret key and IV
		cipher.init(Cipher.DECRYPT_MODE, this.bobSecretKey, this.parameterSpec);

		// Perform the decryption
		return new String(cipher.doFinal(encryptedMessage), java.nio.charset.StandardCharsets.UTF_8);
	}

}
