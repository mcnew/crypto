package symmetric;

import java.util.Base64;

public class SymmetricMain {

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		Alice alice = new Alice();
		Faythe faythe = new Faythe();

		// Alice creates her secret key
		alice.createSecretKey();

		// Alice sends her secret key and IV to Bob through Faythe
		faythe.receiveAliceSecretKey(alice.getSecretKey(), alice.getIv());

		// Bob receives Alice's secret key and IV from Faythe
		bob.receiveAliceSecretKey(faythe.getAliceSecretKey(), faythe.getAliceIv());

		// Bob encrypts a message using Alice's secret key and sends it through Faythe
		faythe.receiveBobMessage(bob.encryptMessage());
		System.out.printf("Encrypted Message (size: %d) %s", faythe.getBobMessage().length,
				Base64.getEncoder().encodeToString(faythe.getBobMessage()));
		System.out.println();

		// Alice receives the encrypted message from Faythe and decrypts it
		String decryptedMessage = alice.decryptBobMessage(faythe.getBobMessage());
		System.out.printf("Decrypted Message: %s", decryptedMessage);
		System.out.println();

		// Note: In this symmetric key exchange scenario, Faythe can read and modify
		// the messages.
		// This highlights the vulnerability of symmetric key exchange without secure
		// channels.
	}

}
