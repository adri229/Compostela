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
 * Hostel es la clase que se utiliza para instanciar los distintos
 * albergues por los cuales pasara el peregrino y sellara su compostela
 * La clase Hostel contiene el metodo stampCompostela que sella la 
 * compostela del peregrino
 * 
 * @author: Adrian Celix Fernandez
 * @author: Tamara Gonzalez Gomez
 */

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
	
	public Hostel (String id, String date, String address,String incidents,
			String publicKeyFile, String privateKeyFile){
		
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
	
	/*
	 * Metodo que se utiliza para crear una String como forma de visualizacion 
	 * de los datos del albergue.
	 * @return String: Devuelve todos los datos del albergue en forma de String.
	 */
	private String createStringData() {
		StringBuilder str = new StringBuilder();

		str.append("Data Hostel "+id).append(System.lineSeparator());
		str.append("Date: ").append(this.date).append(System.lineSeparator());
		str.append("Address: ").append(this.address).append(System.lineSeparator());
		str.append("Incidents: ").append(this.incidents).append(System.lineSeparator());
		
		return str.toString();
	}
	
	/*
	 * Metodo que sella la compostela del peregrino. Se anhaden al paquete compostela los
	 * datos propios del albergue cifrados con la clave secreta del albergue (Cifrado simetrico DES),
	 * se anhade tambien la clave secreta del albergue cifrada con su clave privada
	 * (Cifrado asimetrico RSA), por ultimo se anhade la firma del albergue.
	 * @param: compostela: Mapa que contiene todos los datos del peregrino
	 * @param: publicOffice: Clave publica de la oficina que se usara para cifrar los datos 
	 * del albergue
	 * @return Map<String,byte[]>: Devuelve el mapa compostela con los datos del peregrino mas los 
	 * datos del albergue.  
	 */
	public Map<String,byte[]> stampCompostela(Map<String,byte[]> compostela, PublicKey publicOffice) {
		encrytpSecretKey = this.cipherSecretKey(publicOffice, secretKey);
		this.signature = this.signatureData(compostela.get(Member.signaturePilgrimCode));
		
		compostela.put(Member.dataHostelCode+id, this.dataEncrypted);
		compostela.put(Member.secretKeyHostelCode+id, this.encrytpSecretKey);
		compostela.put(Member.signatureHostelCode+id, this.signature);
		
		return compostela;
	}
	
	/*
	 * Metodo que se utiliza para firmar los datos del albergue. Primero
	 * realiza un resumen de los datos y luego los firma.
	 * @return byte[]: Devuelve la firma del albergue en un array de bytes.
	 */
	private byte[] signatureData(byte[] signPilgrim) {
		byte[] sign=null;
		try {
			/*
			MessageDigest messageDigest = MessageDigest.getInstance(Member.hashingAlgorithm);
			messageDigest.update(signPilgrim);
			messageDigest.update(dataEncrypted);
			byte[] hash = messageDigest.digest();
*/	
			Signature signature = Signature.getInstance(Member.signatureAlgorithm, Member.provider);
			signature.initSign(this.privateKey);
			signature.update(signPilgrim);
			signature.update(this.dataEncrypted);
			sign = signature.sign();

		} catch (NoSuchAlgorithmException | NoSuchProviderException 
				| InvalidKeyException | SignatureException e) {
			System.err.println("Error in sign package hostel: "+ this.id + e.getMessage());
		}
		
		return sign;
	}
}
