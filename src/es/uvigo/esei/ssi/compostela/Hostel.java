package es.uvigo.esei.ssi.compostela;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

import javax.crypto.SecretKey;

public class Hostel extends Member {

	private String data;
	private String id;
	private String date;
	private String address;
	private String incidents;
	private SecretKey secretKey;
	private byte[] dataBytes;
	private byte[] dataEncrypted;
	private byte[] encrytpSecretKey;
	private byte[] signature;
	
	public Hostel (String id, String date, String address,String incidents,String publicKeyFile, String privateKeyFile){
		
		super(publicKeyFile, privateKeyFile);
		this.id = id;
		this.date = date;
		this.address = address;
		this.incidents = incidents;
		this.data = this.createStringData();
		this.dataBytes = this.data.getBytes();
		this.secretKey = this.createSecretKey();
		this.dataEncrypted = this.cipherData(dataBytes, secretKey);
	}

	private String createStringData() {
		StringBuilder str = new StringBuilder();

		str.append("Data Hostel "+id).append(System.lineSeparator());
		str.append("Date: ").append(this.date).append(System.lineSeparator());
		str.append("Address: ").append(this.address).append(System.lineSeparator());
		str.append("Incidents: ").append(this.incidents).append(System.lineSeparator());
		
		return str.toString();
	}

	public Map<String,byte[]> stampCompostela(Map<String,byte[]> compostela, PublicKey publicOffice) {
		
		//add data hostel to compostela
		encrytpSecretKey = this.cipherSecretKey(publicOffice, secretKey);
		this.signature = this.signatureData(compostela.get("PILGRIM_SIGNATURE"));
		
		compostela.put("HOSTEL_DATA"+id, this.dataEncrypted);
		compostela.put("HOSTEL_SECRETKEY"+id, this.encrytpSecretKey);
		compostela.put("HOSTEL_SIGNATURE"+id, this.signature);
		
		return compostela;
	}

	private byte[] signatureData(byte[] signPilgrim) {
		byte[] sign=null;
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(signPilgrim);
			messageDigest.update(dataEncrypted);
			byte[] hash = messageDigest.digest();

			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initSign(this.privateKey);
			signature.update(hash);
			sign = signature.sign();

		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en resumen paquete" + e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return sign;
	}


}
