package kem;

public class Faythe {

	private byte[] alicePublicKey;

	private byte[] bobEncapsulation;

	private byte[] bobIv;

	private byte[] bobMessage;

	public void receiveAlicePublicKey(byte[] alicePublicKey) {
		this.alicePublicKey = alicePublicKey;
	}

	public void receiveBobEncapsulationAndIv(byte[] bobEncapsulation, byte[] iv) {
		this.bobEncapsulation = bobEncapsulation;
		this.bobIv = iv;
	}

	public void receiveBobMessage(byte[] encryptMessage) {
		this.bobMessage = encryptMessage;
	}

	public byte[] getAlicePublicKey() {
		return this.alicePublicKey;
	}

	public byte[] getBobEncapsulation() {
		return this.bobEncapsulation;
	}

	public byte[] getBobIv() {
		return this.bobIv;
	}

	public byte[] getBobMessage() {
		return this.bobMessage;
	}

}
