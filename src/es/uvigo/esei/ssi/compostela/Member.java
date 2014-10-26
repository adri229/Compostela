package es.uvigo.esei.ssi.compostela;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

public class Member {
	
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

	private void loadKeys() {
		
		Security.addProvider(new BouncyCastleProvider()); 
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
			PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
			this.privateKey = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

			/*** 4 Recuperar clave PUBLICA del fichero */
			// 4.1 Leer datos binarios x809
			byte[] bufferPub = new byte[5000];
			in = new FileInputStream(this.publicKeyFile);
			in.read(bufferPub, 0, 5000);
			in.close();

			// 4.2 Recuperar clave publica desde datos codificados en formato
			// X509
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
	
	
	//Method what use in symmetric cipher
	protected SecretKey createSecretKey(){
		KeyGenerator generadorAES=null;
		 SecretKey secretKey=null;
		try {
			generadorAES = KeyGenerator.getInstance("DES");
			generadorAES.init(56);
	        secretKey = generadorAES.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error in create SecretKey " +e.getMessage());
		}
        return secretKey;
		
	}
	
	protected byte[] cipherData(byte[] bytes, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
			bufferCifrado = cifrador.doFinal(bytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		}
		return bufferCifrado;
	}
	
	
	protected byte[] cipherSecretKey(PublicKey clavePublica, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, clavePublica); 
			bufferCifrado = cipher.doFinal(secretKey.getEncoded());
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
		return bufferCifrado;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
	
}
