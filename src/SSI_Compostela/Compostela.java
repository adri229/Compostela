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
		Peregrino p = new Peregrino(....);
		Albergue a1 = new Albergue();
		Albergue a2 = new Albergue();
		Oficina o = new Oficina(...);
		Paquete compostela = p.generarCompostela(o.getPublicKey());
		*/
	}

	
}

class Participante{
	protected PublicKey publicKey;
	protected PrivateKey privateKey;
	protected File publicKeyFile;
	protected File privateKeyFile;
	
	
	public Participante(String pathClavePublica, String pathClavePrivada){
		this.privateKeyFile = new File(pathClavePrivada);
		this.publicKeyFile = new File(pathClavePublica);
		loadKeys();
	}
	
	protected void loadKeys(){
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC
		try {
			KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
			/*** 2 Recuperar clave Privada del fichero */
			// 2.1 Leer datos binarios PKCS8
			byte[] bufferPriv = new byte[5000];
			FileInputStream in = new FileInputStream(this.privateKeyFile);
			in.read(bufferPriv, 0, 5000);
			in.close();

			// 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
			PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
			this.privateKey = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
			
			/*** 4 Recuperar clave PUBLICA del fichero */
			// 4.1 Leer datos binarios x809
			byte[] bufferPub = new byte[5000];
			in = new FileInputStream(this.publicKeyFile);
			in.read(bufferPub, 0, 5000);
			in.close();

			// 4.2 Recuperar clave publica desde datos codificados en formato X509
			X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
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
	
	protected SecretKey createSecretKey(){
		KeyGenerator generadorDES;
		SecretKey secretKey=null;
		
		try {
			generadorDES = KeyGenerator.getInstance("DES");
			generadorDES.init(56);
			secretKey = generadorDES.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en la creacion de la clave secreta");
		}
		return secretKey;
	}
	
	protected Bloque cipherData(String name, byte[] bytes, SecretKey secretKey){
		byte[] bufferCifrado=null;
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
		return new Bloque(name,bufferCifrado);
	}
	
	protected Bloque cipherSecretKey(PublicKey  clavePublica, SecretKey secretKey){
		//Oficina oficina = new Oficina();
		byte[] bufferCifrado=null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, clavePublica);  // Cifra con la clave publica
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
		return new Bloque("secretKey",bufferCifrado);
	}
	
	public PublicKey getPublicKey(){
		return publicKey;
	}
}

// Genera compostela
class Peregrino extends Participante{

	private String name;
	private String surname;
	private String DNI;
	private String date;
	private String address;
	private String motivations;
	private SecretKey secretKey;
	byte[] nameBytes = name.getBytes();
	byte[] surnameBytes = surname.getBytes();
	byte[] DNIBytes = DNI.getBytes();
	byte[] dateBytes = date.getBytes();
	byte[] addressBytes = address.getBytes();
	byte[] motivationsBytes = motivations.getBytes();

	
	public Peregrino(String name, String surname, String DNI, String date, String address, 
			String motivations, String publicKeyFile, String privateKeyFile) {
		super(publicKeyFile, privateKeyFile);
		this.name = name;
		this.surname = surname;
		this.DNI = DNI;
		this.date = date;
		this.address = address;
		this.motivations = motivations;
		//this.publicKeyFile = new File(publicKeyFile);
		//this.privateKeyFile = new File(privateKeyFile);
		this.secretKey = createSecretKey();

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
	
	
	public Paquete generarCompostela(PublicKey publicaOficina){
		//Cifrar datos
		Paquete paquete = new Paquete();
		paquete.anadirBloque("name", cipherData("name",nameBytes,this.secretKey));
		paquete.anadirBloque("surname", cipherData("surname",surnameBytes,this.secretKey));
		paquete.anadirBloque("DNI", cipherData("DNI",DNIBytes,this.secretKey));
		paquete.anadirBloque("date", cipherData("date",dateBytes,this.secretKey));
		paquete.anadirBloque("address", cipherData("address",addressBytes,this.secretKey));
		paquete.anadirBloque("motivations", cipherData("motivations",motivationsBytes,this.secretKey));
		
		//Cifrar Clave Secreta
		
		paquete.anadirBloque("secretKey", cipherSecretKey(publicaOficina, secretKey)); 
		
		//Firmar
		paquete.anadirBloque("sign", signatureData()); 
		
		return paquete;
	}
	/*
	private Bloque cipherData(String name, byte[] bytes){
		byte[] bufferCifrado=null;
		try {
			Cipher cifrador = Cipher.getInstance("DES", "BC");
			cifrador.init(Cipher.ENCRYPT_MODE, this.secretKey);  
			System.out.println("3a. Cifrar con clave publica");
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
		return new Bloque(name,bufferCifrado);
	}
	*/
	
	/*
	private Bloque cipherSecretKey(){
		Oficina oficina = new Oficina();
		byte[] bufferCifrado=null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, oficina.getPublicKey());  // Cifra con la clave publica
		    System.out.println("3a. Cifrar con clave publica");
			bufferCifrado = cipher.doFinal(this.secretKey.getEncoded());
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
		return new Bloque("secretKey",bufferCifrado);
	}
	*/
	
	private Bloque signatureData(){
		byte[] sign = null;
		try {
			Signature signature = Signature.getInstance("MD5withRSA","BC");
			signature.initSign(privateKey);
			signature.update(this.nameBytes);
			signature.update(this.surnameBytes);
			signature.update(this.DNIBytes);
			signature.update(this.dateBytes);
			signature.update(this.addressBytes);
			signature.update(this.motivationsBytes);
			sign = signature.sign();  // FRAN	
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error en la firma"+e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en la firma"+e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error en la firma"+e.getMessage());
		}
		return new Bloque("signature",sign);
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
class Albergue extends Participante{
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
	
	
	
	Albergue(String idAlbergue, String dateAlbergue, String addressAlbergue, String incidentsAlbergue, String publicKeyFile, String privateKeyFile){
		super(publicKeyFile, privateKeyFile);
		this.idAlbergue = idAlbergue;
		this.dateAlbergue = dateAlbergue;
		this.addressAlbergue = addressAlbergue;
		this.incidentsAlbergue = incidentsAlbergue;
		this.summary=null;
		this.id=idAlbergue.getBytes();
		this.date=dateAlbergue.getBytes();
		this.address=addressAlbergue.getBytes();
		this.incidents=incidentsAlbergue.getBytes();
		this.sign=null;

		this.secretKey = this.createSecretKey(); 
	}
	
	public Paquete sellarCompostela(Paquete paquete, PublicKey publicaOficina){
		this.addDataHosteltoPackage(paquete);
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(paquete.getBloque("name").getContenido());
			messageDigest.update(paquete.getBloque("surname").getContenido());
			messageDigest.update(paquete.getBloque("DNI").getContenido());
			messageDigest.update(paquete.getBloque("date").getContenido());
			messageDigest.update(paquete.getBloque("address").getContenido());
			messageDigest.update(paquete.getBloque("motivations").getContenido());
			messageDigest.update(paquete.getBloque("secretKey").getContenido());
			messageDigest.update(paquete.getBloque("signature").getContenido());
			messageDigest.update(id);
			messageDigest.update(date);
			messageDigest.update(address);
			messageDigest.update(incidents);
			
			Signature signature = Signature.getInstance("MD5withRSA","BC");
			signature.initSign(this.privateKey);
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
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_SECRET_KEY", this.cipherSecretKey(publicaOficina, secretKey));
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_SIGN", new Bloque("signAlbergue",sign));
		return paquete;
	}
	
	
	private void addDataHosteltoPackage(Paquete paquete){
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_ID", this.cipherData("idAlbergue", this.id,this.secretKey));
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_DATE", this.cipherData("idAlbergue", this.date,this.secretKey));
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_ADDRESS", this.cipherData("idAlbergue", this.address,this.secretKey));
		paquete.anadirBloque("ALBERGUE_"+idAlbergue+"_INCIDENTS", this.cipherData("idAlbergue", this.incidents,this.secretKey));
	}
	
}

// Desempaqueta compostela
class Oficina extends Participante{
	
	Oficina(String publicKeyFile, String privateKeyFile){
		super(publicKeyFile, privateKeyFile);
		
	}
	
	public boolean desempaquetarCompostela(Paquete paquete, Vector<String> idAlbergue, PublicKey publicKeyPeregrino){
		//Extraer firmas albergue por ID
		
		SecretKey secretKey = null;
		byte[] date = null;
		byte[] address = null;
		byte[] incidents = null;
		Signature sign=null;
		
        for(int i = 0; i<idAlbergue.size(); i++){
        	String id = idAlbergue.get(i);
        	date = paquete.getBloque("ALBERGUE"+id+"DATE").getContenido();
        	address = paquete.getBloque("ALBERGUE"+id+"ADDRESS").getContenido();
        	incidents = paquete.getBloque("ALBERGUE"+id+"INCIDENTS").getContenido();
        	//secretKey = paquete.getBloque("ALBERGUE"+id+"SECRET_KEY").getContenido();
        }
		
		
		
		
	
		
		
		
		
		
		
		
		
		return false;
		
		
	}
	
	// recuperar clave secreta  (ver AlmacenarClaves.java) descifrando con KR_oficina
	// descifrar componentes del peregrino con esa clave secreta
	// validar firma del peregrino con KU_peregrino
	
	// Para cada albergue
	//    validar firma del albergue con KU_albergue
	
}

/**
 * ID albergue?
 * instancia oficina?
 * 
 */
