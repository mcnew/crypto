package kem;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KemMain {

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		Alice alice = new Alice();
		Faythe faythe = new Faythe();

		// Alice generates her key pair
		alice.generateKeyPair();

		// Alice sends her public key to Bob through Faythe
		faythe.receiveAlicePublicKey(alice.getPublicKey());

		// Bob would proceed to use the public key received from Faythe to generate an
		// encapsulation, deriving a shared secret key and sending the encapsulation
		// back to Alice (through Faythe) along with the IV
		faythe.receiveBobEncapsulationAndIv(
				bob.receiveAlicePublicKeyAndGenerateEncapsulation(faythe.getAlicePublicKey(), KemMain::deriveKey),
				bob.getIv());

		// Alice receives the encapsulation from Faythe and derives the shared secret
		// key
		alice.receiveBobEncapsulationAndIv(faythe.getBobEncapsulation(), faythe.getBobIv(), KemMain::deriveKey);

		// At this point, Alice and Bob have established a shared secret key.
		// Bob sends an encrypted message to Alice via Faythe
		faythe.receiveBobMessage(bob.encryptMessage());
		System.out.printf("Encrypted Message (size: %d) %s", faythe.getBobMessage().length,
				Base64.getEncoder().encodeToString(faythe.getBobMessage()));
		System.out.println();

		// Alice receives the encrypted message from Faythe and decrypts it
		String decryptedMessage = alice.decryptBobMessage(faythe.getBobMessage());
		System.out.printf("Decrypted Message: %s", decryptedMessage);
		System.out.println();

		// Note: In this KEM-based key exchange scenario, Faythe cannot read the
		// messages.
	}

	public static SecretKey deriveKey(String algorithm, byte[] sharedSecret) {
		// Simple key derivation function (for demonstration purposes only)
		// In practice, use a proper KDF like HKDF
		try {
			byte[] derived = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
			return new SecretKeySpec(derived, algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

}
