package symmetric;

import java.util.Base64;

public class SymmetricMain {

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		Alice alice = new Alice();
		Mallory mallory = new Mallory();

		// Alice creates her secret key
		alice.createSecretKey();

		// Alice sends her secret key and IV to Bob through Mallory
		mallory.receiveAliceSecretKey(alice.getSecretKey(), alice.getIv());

		// Bob receives Alice's secret key and IV from Mallory
		bob.receiveAliceSecretKey(mallory.getAliceSecretKey(), mallory.getAliceIv());

		// Bob encrypts a message using Alice's secret key and sends it through Mallory
		mallory.receiveBobMessage(bob.encryptMessage());
		System.out.printf("Encrypted Message (size: %d) %s", mallory.getBobMessage().length,
				Base64.getEncoder().encodeToString(mallory.getBobMessage()));
		System.out.println();

		// Alice receives the encrypted message from Mallory and decrypts it
		String decryptedMessage = alice.decryptBobMessage(mallory.getBobMessage());
		System.out.printf("Decrypted Message: %s", decryptedMessage);
		System.out.println();

		// Note: In this symmetric key exchange scenario, Mallory can read and modify
		// the messages.
		// This highlights the vulnerability of symmetric key exchange without secure
		// channels.
	}

}
