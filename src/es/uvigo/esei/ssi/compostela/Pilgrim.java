package es.uvigo.esei.ssi.compostela;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;

import javax.crypto.SecretKey;

/*
 * Pilgrim es la clase que contiene todos los datos del peregrino
 * que conforman el paquete compostela. Esta clase genera el paquete
 * que contiene los datos cifrados dle peregrino, su clave secreta 
 * cifrada y su firma.
 * 
 *  @author: Adrian Celix Fernandez
 *  @author: Tamara Gonzalez Gomez 
 */

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
	
	/*
	 * Metodo que se utiliza para crear una String como forma de visualizacion 
	 * de los datos del peregrino.
	 * @return String: Devuelve todos los datos del peregrino en forma de String.
	 */
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
	
	/*
	 * Metodo que se utiliza para firmar los datos del peregrino. Primero
	 * realiza un resumen de los datos y luego los firma.
	 * @return byte[]: Devuelve la firma del peregrino en un array de bytes.
	 */
	private byte[] signatureData() {
		byte[] sign = null;
		try {
			Signature signature = Signature.getInstance(Member.signatureAlgorithm, Member.provider);
			signature.initSign(privateKey);
			signature.update(this.dataEncrypted);
			sign = signature.sign();
		} catch (InvalidKeyException | SignatureException |
			NoSuchAlgorithmException | NoSuchProviderException e) {
			System.err.println("Error in sign package pilgrim: " + e.getMessage());
		} 
		
		return sign;
	}
	
	/*
	 * Metodo que genera el paquete compostela. En la compostela se introducen todos los
	 * datos del peregrino cifrados con la clave secreta del peregrino (Cifrado simetrico DES),
	 * se introduce la clave secreta del peregrino cifrada con la publica de la oficina
	 * (Cifrado asimetrico RSA) y se introduce la firma del peregrino.
	 * @param publicOffice: Clave publica de la oficina que se utiliza para cifrar la clave
	 * secreta del peregrino.
	 * @param compostela: Mapa vacio que se rellenara con los datos del peregrino
	 * @return Map<String,byte[]>: Devuelve el mapa Compostela rellenado con los datos del peregrino  
	 */
	public Map<String,byte[]> generateCompostela(PublicKey publicOffice, Map<String,byte[]> compostela) {	
		encrytpSecretKey = this.cipherSecretKey(publicOffice, secretKey);
		this.signature = this.signatureData();

		compostela.put(Member.dataPilgrimCode, this.dataEncrypted);
		compostela.put(Member.secretKeyPilgrimCode, this.encrytpSecretKey);
		compostela.put(Member.signaturePilgrimCode, this.signature);
		
		return compostela;
	}
}


