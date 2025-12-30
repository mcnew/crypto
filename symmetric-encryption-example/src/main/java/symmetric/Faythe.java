package symmetric;

public class Faythe {

	private byte[] aliceSecretKey;

	private byte[] aliceIv;

	private byte[] bobMessage;

	public void receiveAliceSecretKey(byte[] aliceSecretKey, byte[] aliceIv) {
		this.aliceSecretKey = aliceSecretKey;
		this.aliceIv = aliceIv;
	}

	public void receiveBobMessage(byte[] bobMessage) {
		this.bobMessage = bobMessage;
	}

	public byte[] getAliceSecretKey() {
		return this.aliceSecretKey;
	}

	public byte[] getAliceIv() {
		return this.aliceIv;
	}

	public byte[] getBobMessage() {
		return this.bobMessage;
	}

}
