package asymmetric;

import java.util.Base64;

public class AsymmetricMain {

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		Alice alice = new Alice();
		Faythe faythe = new Faythe();

		// Alice creates her key pair
		alice.createKeyPair();

		// Alice sends her public key to Bob through Faythe
		faythe.receiveAlicePublicKey(alice.getPublicKey());

		// Bob receives Alice's public key from Faythe
		bob.receiveAlicePublicKey(faythe.getAlicePublicKey());

		// Bob encrypts a message using Alice's public key and sends it through Faythe
		faythe.receiveBobMessage(bob.encryptMessage());
		System.out.printf("Encrypted Message (size: %d) %s", faythe.getBobMessage().length,
				Base64.getEncoder().encodeToString(faythe.getBobMessage()));
		System.out.println();

		// Alice receives the encrypted message from Faythe and decrypts it
		String decryptedMessage = alice.decryptBomMessage(faythe.getBobMessage());
		System.out.printf("Decrypted Message: %s", decryptedMessage);
		System.out.println();

		// Note: In this asymmetric key exchange scenario, Faythe cannot read the
		// messages
		// But the size of the encrypted messages grows with the key size, which may
		// leak some information.
	}

}
