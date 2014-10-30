package es.uvigo.esei.ssi.compostela;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/*
 * Member es una superclase de la cual heredan las clases derivadas:
 * Pilgrim, Hostel y Office. Se emplea para los metodos y atributos
 * comunes de dichas clases.
 * 
 * @author: Adrian Celix Fernandez
 * @author: Tamara Gonzalez Gomez 
 */

public class Member {
	
	public static final String symmetricCipher = "DES";
	public static final String asymmetricCipher = "RSA";
	public static final String provider = "BC";
	public static final String hashingAlgorithm = "MD5";
	public static final String signatureAlgorithm = "MD5withRSA";
	public static final String cipherMethod = "DES/ECB/PKCS5Padding";
	
	public final static String dataPilgrimCode = "PILGRIM_DATA";
	public final static String secretKeyPilgrimCode = "PILGRIM_SECRETKEY";
	public final static String signaturePilgrimCode = "PILGRIM_SIGNATURE";
	public final static String dataHostelCode = "HOSTEL_DATA";
	public final static String secretKeyHostelCode = "HOSTEL_SECRETKEY";
	public final static String signatureHostelCode = "HOSTEL_SIGNATURE";
	
	protected PublicKey publicKey;
	protected PrivateKey privateKey;
	protected KeyPair keypair;
	protected File publicKeyFile;
	protected File privateKeyFile;
	
	public Member(String pathPublicKey, String pathPrivateKey) {
		this.privateKeyFile = new File(pathPrivateKey);
		this.publicKeyFile = new File(pathPublicKey);
		loadKeys();
	}

	
	
	// Metodo que carga las claves publica y privada de las clases derivadas 
	private void loadKeys() {
		
		Security.addProvider(new BouncyCastleProvider()); 
		try {
			KeyFactory keyFactoryRSA = KeyFactory.getInstance(Member.asymmetricCipher, Member.provider);
			
			byte[] bufferPriv = new byte[5000];
			byte[] bufferPub = new byte[5000];
			try(FileInputStream inPrivateKey = new FileInputStream(this.privateKeyFile);
				FileInputStream inPublicKey = new FileInputStream(this.publicKeyFile)){
				inPrivateKey.read(bufferPriv, 0, 5000);
				inPublicKey.read(bufferPub, 0, 5000);
			}
			
			PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
			this.privateKey = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

			X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
			this.publicKey = keyFactoryRSA.generatePublic(clavePublicaSpec);

		} catch (NoSuchAlgorithmException | NoSuchProviderException |
				IOException | InvalidKeySpecException e) {
			System.err.println("Error in load keys " + e.getMessage());
		}
	}
	
	
	/*
	 * Metodo que se emplea en el cifrado simetrico
	 * @return: SecretKey generada mediante algoritmo DES. 
	 */
	
	protected SecretKey createSecretKey(){
		KeyGenerator generadorAES=null;
		 SecretKey secretKey=null;
		try {
			generadorAES = KeyGenerator.getInstance(Member.symmetricCipher);
			generadorAES.init(56);
	        secretKey = generadorAES.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error in create SecretKey " +e.getMessage());
		}
        return secretKey;
		
	}
	
	/*
	 * Metodo que se emplea para cifrar datos.
	 * @param bytes: Array de bytes cuyo contenido es los datos que se desea firma
	 * @param secretKey: Objeto SecretKey con la cual se firman los datos del array de bytes
	 * @return byte[]: El metodo devuelve los datos cifrados en un array de bytes.
 	 */
	protected byte[] cipherData(byte[] bytes, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance(Member.cipherMethod);
			cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
			bufferCifrado = cifrador.doFinal(bytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
				IllegalBlockSizeException | BadPaddingException | 
				InvalidKeyException e) {
			System.err.println("Error in cipher data " + e.getMessage());
		} 
		
		return bufferCifrado;
	}
	
	/*
	 * Metodo que cifra una clave secreta
	 * @param publicKey: Clave publica con la que se cifra la clave secreta
	 * @param secretKey: Clave secreta que se desea firmar
	 * @return byte[]: Devuelve la clave secreta cifrada en un array de bytes
	 */
	protected byte[] cipherSecretKey(PublicKey publicKey, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(Member.asymmetricCipher, Member.provider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
			bufferCifrado = cipher.doFinal(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException | IllegalBlockSizeException |
				BadPaddingException | InvalidKeyException e) {
			System.err.println("Error in encrypt SecretKey " + e.getMessage());
		}
		
		return bufferCifrado;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
	
}
