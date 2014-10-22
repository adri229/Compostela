package SSI_Compostela;

import java.io.BufferedInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Compostela {

	public static void main(String[] args) {
		/*
		 * Peregrino p = new Peregrino(....); Albergue a1 = new Albergue();
		 * Albergue a2 = new Albergue(); Oficina o = new Oficina(...); Paquete
		 * compostela = p.generarCompostela(o.getPublicKey());
		 */
		
		Peregrino pilgrim = new Peregrino("adrian", "fernandez", "44478888Q", "22/10/2014", "Camelias", "religion", "Peregrino.publica", "Peregrino.privada");
		Albergue hostel1 = new Albergue("1", "23/10/1014", "valenzana", "n/a", "Albergue1.publica", "Albergue1.privada");
		Albergue hostel2 = new Albergue("1", "24/10/1014", "lagunas", "n/a", "Albergue2.publica", "Albergue2.privada");
		Oficina oficina = new Oficina("Oficina.publica", "Oficina.privada");
		Vector<String> idAlbergue = new Vector<String>();
		idAlbergue.add("1");
		idAlbergue.add("2");
		Map<String,PublicKey> publicKeys = new HashMap<String,PublicKey>(); 
		publicKeys.put("1", hostel1.getPublicKey());
		publicKeys.put("2", hostel2.getPublicKey());
		Paquete paquete = pilgrim.generarCompostela(pilgrim.getPublicKey());
		paquete = hostel1.sellarCompostela(paquete, oficina.getPublicKey());
		paquete = hostel2.sellarCompostela(paquete, oficina.getPublicKey());
		oficina.desempaquetarCompostela(paquete, idAlbergue, pilgrim.getPublicKey(), publicKeys);
	}

}

class Participante {
	protected PublicKey publicKey;
	protected PrivateKey privateKey;
	protected File publicKeyFile;
	protected File privateKeyFile;

	public Participante(String pathClavePublica, String pathClavePrivada) {
		this.privateKeyFile = new File(pathClavePrivada);
		this.publicKeyFile = new File(pathClavePublica);
		loadKeys();
	}

	protected void loadKeys() {
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider
															// BC
		try {
			KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
			/*** 2 Recuperar clave Privada del fichero */
			// 2.1 Leer datos binarios PKCS8
			byte[] bufferPriv = new byte[5000];
			FileInputStream in = new FileInputStream(this.privateKeyFile);
			in.read(bufferPriv, 0, 5000);
			in.close();

			// 2.2 Recuperar clave privada desde datos codificados en formato
			// PKCS8
			PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(
					bufferPriv);
			this.privateKey = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

			/*** 4 Recuperar clave PUBLICA del fichero */
			// 4.1 Leer datos binarios x809
			byte[] bufferPub = new byte[5000];
			in = new FileInputStream(this.publicKeyFile);
			in.read(bufferPub, 0, 5000);
			in.close();

			// 4.2 Recuperar clave publica desde datos codificados en formato
			// X509
			X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(
					bufferPub);
			this.publicKey = keyFactoryRSA.generatePublic(clavePublicaSpec);

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (FileNotFoundException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (IOException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		}

	}

	protected SecretKey createSecretKey() {
		KeyGenerator generadorDES;
		SecretKey secretKey = null;

		try {
			generadorDES = KeyGenerator.getInstance("DES");
			generadorDES.init(56);
			secretKey = generadorDES.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en la creacion de la clave secreta");
		}
		return secretKey;
	}

	protected Bloque cipherData(String name, byte[] bytes, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance("DES", "BC");
			cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
			System.out.println("Cifrar con clave secreta");
			bufferCifrado = cifrador.doFinal(bytes);
			System.out.println("TEXTO CIFRADO");
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		}
		return new Bloque(name, bufferCifrado);
	}

	protected Bloque cipherSecretKey(PublicKey clavePublica, SecretKey secretKey) {
		// Oficina oficina = new Oficina();
		byte[] bufferCifrado = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, clavePublica); // Cifra con la
															// clave publica
			System.out.println("3a. Cifrar con clave publica");
			bufferCifrado = cipher.doFinal(secretKey.getEncoded());
			System.out.println("TEXTO CIFRADO");
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		}
		return new Bloque("secretKey", bufferCifrado);
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
}

// Genera compostela
class Peregrino extends Participante {

	private String name;
	private String surname;
	private String DNI;
	private String date;
	private String address;
	private String motivations;
	private SecretKey secretKey;
	byte[] nameBytes = null;
	byte[] surnameBytes = null;
	byte[] DNIBytes = null;
	byte[] dateBytes = null;
	byte[] addressBytes = null;
	byte[] motivationsBytes = null;

	public Peregrino(String name, String surname, String DNI, String date,
			String address, String motivations, String publicKeyFile,
			String privateKeyFile) {
		super(publicKeyFile, privateKeyFile);
		this.name = name;
		this.surname = surname;
		this.DNI = DNI;
		this.date = date;
		this.address = address;
		this.motivations = motivations;
		this.publicKeyFile = new File(publicKeyFile);
		this.privateKeyFile = new File(privateKeyFile);
		this.secretKey = createSecretKey();
		nameBytes = name.getBytes();
		surnameBytes = surname.getBytes();
		DNIBytes = DNI.getBytes();
		dateBytes = date.getBytes();
		addressBytes = address.getBytes();
		motivationsBytes = motivations.getBytes();

	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSurname() {
		return surname;
	}

	public void setSurname(String surname) {
		this.surname = surname;
	}

	public String getDNI() {
		return DNI;
	}

	public void setDNI(String dNI) {
		DNI = dNI;
	}

	public Paquete generarCompostela(PublicKey publicaOficina) {
		// Cifrar datos
		Paquete paquete = new Paquete();
		paquete.anadirBloque("PILGRIM"+"name",cipherData("name", nameBytes, this.secretKey));
		paquete.anadirBloque("PILGRIM"+"surname",cipherData("surname", surnameBytes, this.secretKey));
		paquete.anadirBloque("PILGRIM"+"DNI", cipherData("DNI", DNIBytes, this.secretKey));
		paquete.anadirBloque("PILGRIM"+"date",cipherData("date", dateBytes, this.secretKey));
		paquete.anadirBloque("PILGRIM"+"address",cipherData("address", addressBytes, this.secretKey));
		paquete.anadirBloque("PILGRIM"+"motivations",cipherData("motivations", motivationsBytes, this.secretKey));
		
		System.out.println("motiv pilgrim: "+new String(motivationsBytes));
		// Cifrar Clave Secreta

		paquete.anadirBloque("PILGRIM"+"secretKey",cipherSecretKey(publicaOficina, secretKey));

		// Firmar
		paquete.anadirBloque("PILGRIM"+"signature", signatureData());

		return paquete;
	}

	/*
	 * private Bloque cipherData(String name, byte[] bytes){ byte[]
	 * bufferCifrado=null; try { Cipher cifrador = Cipher.getInstance("DES",
	 * "BC"); cifrador.init(Cipher.ENCRYPT_MODE, this.secretKey);
	 * System.out.println("3a. Cifrar con clave publica"); bufferCifrado =
	 * cifrador.doFinal(bytes); System.out.println("TEXTO CIFRADO"); } catch
	 * (NoSuchAlgorithmException | NoSuchProviderException |
	 * NoSuchPaddingException e) { System.out.println("Error en el cifrado " +
	 * e.getMessage()); } catch (IllegalBlockSizeException e) {
	 * System.out.println("Error en el cifrado " + e.getMessage()); } catch
	 * (BadPaddingException e) { System.out.println("Error en el cifrado " +
	 * e.getMessage()); } catch (InvalidKeyException e) {
	 * System.out.println("Error en el cifrado " + e.getMessage()); } return new
	 * Bloque(name,bufferCifrado); }
	 */

	/*
	 * private Bloque cipherSecretKey(){ Oficina oficina = new Oficina(); byte[]
	 * bufferCifrado=null; Cipher cipher; try { cipher =
	 * Cipher.getInstance("RSA", "BC"); cipher.init(Cipher.ENCRYPT_MODE,
	 * oficina.getPublicKey()); // Cifra con la clave publica
	 * System.out.println("3a. Cifrar con clave publica"); bufferCifrado =
	 * cipher.doFinal(this.secretKey.getEncoded());
	 * System.out.println("TEXTO CIFRADO"); } catch (NoSuchAlgorithmException |
	 * NoSuchProviderException | NoSuchPaddingException e) {
	 * System.out.println("Error en el cifrado " + e.getMessage()); } catch
	 * (IllegalBlockSizeException e) { System.out.println("Error en el cifrado "
	 * + e.getMessage()); } catch (BadPaddingException e) {
	 * System.out.println("Error en el cifrado " + e.getMessage()); } catch
	 * (InvalidKeyException e) { System.out.println("Error en el cifrado " +
	 * e.getMessage()); } return new Bloque("secretKey",bufferCifrado); }
	 */

	private Bloque signatureData() {
		byte[] sign = null;
		try {
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initSign(privateKey);
			signature.update(this.nameBytes);
			signature.update(this.surnameBytes);
			signature.update(this.DNIBytes);
			signature.update(this.dateBytes);
			signature.update(this.addressBytes);
			signature.update(this.motivationsBytes);
			sign = signature.sign(); // FRAN
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error en la firma" + e.getMessage());
		}
		return new Bloque("signature", sign);
	}
}

class Date {

	private int day;
	private int month;
	private int year;

	public Date(int day, int month, int year) {
		super();
		this.day = day;
		this.month = month;
		this.year = year;
	}

	public int getDay() {
		return day;
	}

	public void setDay(int day) {
		this.day = day;
	}

	public int getMonth() {
		return month;
	}

	public void setMonth(int month) {
		this.month = month;
	}

	public int getYear() {
		return year;
	}

	public void setYear(int year) {
		this.year = year;
	}
}

// Sella compostela
class Albergue extends Participante {
	String idAlbergue;
	String dateAlbergue;
	String addressAlbergue;
	String incidentsAlbergue;
	byte[] summary;
	byte[] id;
	byte[] date;
	byte[] address;
	byte[] incidents;
	byte[] sign;
	private SecretKey secretKey;

	Albergue(String idAlbergue, String dateAlbergue, String addressAlbergue,
			String incidentsAlbergue, String publicKeyFile,
			String privateKeyFile) {
		super(publicKeyFile, privateKeyFile);
		this.idAlbergue = idAlbergue;
		this.dateAlbergue = dateAlbergue;
		this.addressAlbergue = addressAlbergue;
		this.incidentsAlbergue = incidentsAlbergue;
		this.summary = null;
		this.id = idAlbergue.getBytes();
		this.date = dateAlbergue.getBytes();
		this.address = addressAlbergue.getBytes();
		this.incidents = incidentsAlbergue.getBytes();
		this.sign = null;

		this.secretKey = this.createSecretKey();
	}

	public Paquete sellarCompostela(Paquete paquete, PublicKey publicaOficina) {
		this.addDataHosteltoPackage(paquete);
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(paquete.getBloque("PILGRIM"+"name").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"surname").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"DNI").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"date").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"address").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"motivations").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"secretKey").getContenido());
			messageDigest.update(paquete.getBloque("PILGRIM"+"signature").getContenido());
			messageDigest.update(id);
			messageDigest.update(date);
			messageDigest.update(address);
			messageDigest.update(incidents);
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
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "SECRET_KEY",
				this.cipherSecretKey(publicaOficina, secretKey));
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "SIGN", new Bloque(
				"signAlbergue", sign));
		return paquete;
	}

	private void addDataHosteltoPackage(Paquete paquete) {
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "ID",
				this.cipherData("idAlbergue"+idAlbergue, this.id, this.secretKey));
		paquete.anadirBloque("ALBERGUE_" + idAlbergue + "DATE",
				this.cipherData("dateAlbergue"+idAlbergue, this.date, this.secretKey));
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "ADDRESS",
				this.cipherData("addressAlbergue+idAlbergue", this.address, this.secretKey));
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "INCIDENTS",
				this.cipherData("incidentesAlbergue+idAlbergue", this.incidents, this.secretKey));
		
		System.out.println("date albergue"+date);
	}

}

// Desempaqueta compostela
class Oficina extends Participante {

	Oficina(String publicKeyFile, String privateKeyFile) {
		super(publicKeyFile, privateKeyFile);

	}

	public void desempaquetarCompostela(Paquete paquete,
			Vector<String> idAlbergue, PublicKey publicKeyPeregrino,
			Map<String, PublicKey> publicKeysAlbergue) {
		// Extraer firmas albergue por ID

		byte[] secretKey = null;
		byte[] date = null;
		byte[] address = null;
		byte[] incidents = null;
		byte[] sign = null;
		SecretKey secretKeyObject = null;
		
		byte[] namePilgrim = paquete.getBloque("PILGRIM"+"name").getContenido();
		byte[] surnamePilgrim = paquete.getBloque("PILGRIM"+"address").getContenido();
		byte[] DNIPilgrim = paquete.getBloque("PILGRIM"+"DNI").getContenido();
		byte[] datePilgrim = paquete.getBloque("PILGRIM"+"date").getContenido();
		byte[] addressPilgrim = paquete.getBloque("PILGRIM"+"address").getContenido();
		byte[] motivationsPilgrim = paquete.getBloque("PILGRIM"+"motivations").getContenido();
		byte[] secretKeyPilgrim = paquete.getBloque("PILGRIM"+"secretKey").getContenido();
		byte[] signPilgrim = paquete.getBloque("PILGRIM"+"signature").getContenido();
		
		for (int i = 0; i < idAlbergue.size(); i++) {
			String id = idAlbergue.get(i);
			date = paquete.getBloque("ALBERGUE" + id + "DATE").getContenido();
			address = paquete.getBloque("ALBERGUE" + id + "ADDRESS").getContenido();
			incidents = paquete.getBloque("ALBERGUE" + id + "INCIDENTS").getContenido();
			secretKey = paquete.getBloque("ALBERGUE" + id + "SECRET_KEY").getContenido();
			sign = paquete.getBloque("ALBERGUE" + id + "SIGN").getContenido();
			
			
			
			// Verificar firma Albergue
			try {
				Signature signature = Signature.getInstance("MD5withRSA", "BC");
				signature.initVerify(publicKeysAlbergue.get(id));
				// signature.update(); Que datos se le pasan?
				signature.update(namePilgrim);
				signature.update(surnamePilgrim);
				signature.update(DNIPilgrim);
				signature.update(datePilgrim);
				signature.update(addressPilgrim);
				signature.update(motivationsPilgrim);
				signature.update(secretKeyPilgrim);
				signature.update(signPilgrim);
				signature.update(date);
				signature.update(address);
				signature.update(incidents);
				
				boolean verifySign = signature.verify(sign);
				if (verifySign) {
					System.out.println("Firma verificada");
					// Desencriptar datos albergue
					secretKeyObject = this.decryptSecretKey(secretKey);
					System.out.println("Datos Albergue " + id);
					System.out.println("Date: " + this.decrytpData(date, secretKeyObject));
					System.out.println("Address: " + this.decrytpData(address, secretKeyObject));
					System.out.println("Incidentes " + this.decrytpData(incidents, secretKeyObject));
				} else {
					System.out.println("Error, firma no valida");
				}
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		//Verificar firma Peregrino
		/*
		byte[] namePilgrim = paquete.getBloque("PILGRIM"+"name").getContenido();
		byte[] surnamePilgrim = paquete.getBloque("PILGRIM"+"address").getContenido();
		byte[] DNIPilgrim = paquete.getBloque("PILGRIM"+"DNI").getContenido();
		byte[] datePilgrim = paquete.getBloque("PILGRIM"+"date").getContenido();
		byte[] addressPilgrim = paquete.getBloque("PILGRIM"+"adress").getContenido();
		byte[] motivationsPilgrim = paquete.getBloque("PILGRIM"+"motivations").getContenido();
		byte[] secretKeyPilgrim = paquete.getBloque("PILGRIM"+"secretKey").getContenido();
		byte[] signPilgrim = paquete.getBloque("PILGRIM"+"sign").getContenido();
		*/
		SecretKey secretKeyObjectPilgrim = null;
		boolean verifySignPilgrim = false;
		
		try {
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initVerify(publicKeyPeregrino);
			signature.update(namePilgrim);
			signature.update(surnamePilgrim);
			signature.update(DNIPilgrim);
			signature.update(datePilgrim);
			signature.update(addressPilgrim);
			signature.update(motivationsPilgrim);
			verifySignPilgrim = signature.verify(signPilgrim);
		} catch (InvalidKeyException e) {
			System.out.println("Error, invalid key in verify sign of pilgrim");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error in the creation of the object signature" + e.getMessage());
		} catch (NoSuchProviderException e) {
			System.out.println("Error in the creation of the object signature " + e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error, invalid key in verify sign of pilgrim");
		}
		
		if(verifySignPilgrim){
			//Desencriptar y mostrar datos peregrino
			secretKeyObjectPilgrim = this.decryptSecretKey(secretKeyPilgrim);
			System.out.println("Name: " + this.decrytpData(namePilgrim, secretKeyObjectPilgrim));
			System.out.println("Surname: " + this.decrytpData(surnamePilgrim, secretKeyObjectPilgrim));
			System.out.println("DNI: " + this.decrytpData(DNIPilgrim, secretKeyObjectPilgrim));
			System.out.println("Date: " + this.decrytpData(datePilgrim, secretKeyObjectPilgrim));
			System.out.println("Address: " + this.decrytpData(addressPilgrim, secretKeyObjectPilgrim));
			System.out.println("Motivations: " + this.decrytpData(motivationsPilgrim, secretKeyObjectPilgrim));
		}
	}

	private SecretKey decryptSecretKey(byte[] cipherSecretKey) {
		byte[] buffer=null;
		SecretKey secretKey = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			buffer = cipher.doFinal(cipherSecretKey);
			SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
			DESKeySpec DESspec = new DESKeySpec(buffer);
			secretKey = secretKeyFactoryDES.generateSecret(DESspec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // Hace uso del provider BC
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return secretKey;
	}
	
	private byte[] decrytpData(byte[] data, SecretKey secretKey){
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			data = cipher.update(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return data;
	}

	// recuperar clave secreta (ver AlmacenarClaves.java) descifrando con
	// KR_oficina
	// descifrar componentes del peregrino con esa clave secreta
	// validar firma del peregrino con KU_peregrino

	// Para cada albergue
	// validar firma del albergue con KU_albergue

}
 