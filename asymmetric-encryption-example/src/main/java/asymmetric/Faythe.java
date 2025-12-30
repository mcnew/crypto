package asymmetric;

public class Faythe {

	private byte[] alicePublicKey;

	private byte[] bobMessage;

	public void receiveAlicePublicKey(byte[] alicePublicKey) {
		this.alicePublicKey = alicePublicKey;
	}

	public void receiveBobMessage(byte[] bobMessage) {
		this.bobMessage = bobMessage;
	}

	public byte[] getAlicePublicKey() {
		return this.alicePublicKey;
	}

	public byte[] getBobMessage() {
		return this.bobMessage;
	}

}
