package es.uvigo.esei.ssi.compostela;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

import javax.crypto.SecretKey;


public class Pilgrim extends Member {

	private String data;
	private String name;
	private String surname;
	private String DNI;
	private String date;
	private String address;
	private String motivations;
	private byte[] dataBytes;
	private byte[] dataEncrypted;
	private byte[] encrytpSecretKey;
	private byte[] signature;
	private SecretKey secretKey;

	public Pilgrim(String name, String surname, String DNI, String date,
			String address, String motivations, String publicKeyFile,
			String privateKeyFile) {

		super(publicKeyFile, privateKeyFile);
		this.name = name;
		this.surname = surname;
		this.DNI = DNI;
		this.date = date;
		this.address = address;
		this.motivations = motivations;
		this.data = this.createStringData();
		this.dataBytes = data.getBytes();
		secretKey = this.createSecretKey();
		dataEncrypted = this.cipherData(dataBytes, secretKey);
		
	}
	
	private String createStringData(){
		StringBuilder str = new StringBuilder();

		str.append("Data Pilgrim").append(System.lineSeparator());
		str.append("Name: ").append(this.name).append(System.lineSeparator());
		str.append("Surname: ").append(this.surname).append(System.lineSeparator());
		str.append("DNI: ").append(this.DNI).append(System.lineSeparator());
		str.append("Date: ").append(this.date).append(System.lineSeparator());
		str.append("Address: ").append(this.address).append(System.lineSeparator());
		str.append("Motivations: ").append(this.motivations).append(System.lineSeparator());

		return str.toString();
	}

	private byte[] signatureData() {
		byte[] sign = null;
		try {
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initSign(privateKey);
			signature.update(this.dataEncrypted);
			sign = signature.sign();
		} catch (InvalidKeyException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return sign;
	}
	
	public Map<String,byte[]> generateCompostela(PublicKey publicOffice, Map<String,byte[]> compostela) {
		
		encrytpSecretKey = this.cipherSecretKey(publicOffice, secretKey);
		this.signature = this.signatureData();
		//add data of pilgrim
		compostela.put("PILGRIM_DATA", this.dataEncrypted);
		compostela.put("PILGRIM_SECRETKEY", this.encrytpSecretKey);
		compostela.put("PILGRIM_SIGNATURE", this.signature);
		
		return compostela;
	}
}


