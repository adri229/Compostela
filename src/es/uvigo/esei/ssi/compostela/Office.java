package es.uvigo.esei.ssi.compostela;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class Office extends Member {
	
	private byte[] dataPilgrim;
	private byte[] secretKeyPilgrim;
	private byte[] signPilgrim;
	private byte[] dataHostel;
	private byte[] secretKeyHostel;
	private byte[] signHostel;

	public Office(String pathPublicKey, String pathPrivateKey) {
		super(pathPublicKey, pathPrivateKey);
	}

	public void desempaquetarCompostela(Map<String,byte[]> compostela,
			Vector<String> idHostel, PublicKey publicKeyPilgrim,
			Map<String, PublicKey> publicKeysHostel){
		
		this.dataPilgrim = compostela.get("PILGRIM_DATA");
		this.secretKeyPilgrim = compostela.get("PILGRIM_SECRETKEY");
		this.signPilgrim = compostela.get("PILGRIM_SIGNATURE");
		
		// Hostel
		String id;
		for(int i = 0; i < idHostel.size();i++){
			id = idHostel.get(i); 
			this.signHostel = compostela.get("HOSTEL_SIGNATURE"+id);
			this.dataHostel = compostela.get("HOSTEL_DATA"+id);
			this.secretKeyHostel = compostela.get("HOSTEL_SECRETKEY"+id);
			//Verify Sign
			if(this.verifySignHostel(publicKeysHostel.get(id))){
				System.out.println("Verified signature of hostel "+id);
				SecretKey secretKeyDecrypt = this.decryptSecretKey(this.secretKeyHostel);
				byte[] decryptDataHostel = this.decrytpData(dataHostel, secretKeyDecrypt);
				String str = new String(decryptDataHostel);
				System.out.println(str);
			} else {
				System.out.println("Error, invalid sign of hostel "+id);
			}
		}

		//Pilgrim
		
		
		if(this.verifySignPilgrim(publicKeyPilgrim)){
			System.out.println("Verified signature of pilgrim");
			SecretKey secretKeyDecrypt = this.decryptSecretKey(this.secretKeyPilgrim);
			byte[] decryptDataPilgrim = this.decrytpData(dataPilgrim, secretKeyDecrypt);
			String str = new String(decryptDataPilgrim);
			System.out.println(str);
		} else {
			System.out.println("Error, invalid sign of pilgrim");
		}
		
	}
	
	private boolean verifySignHostel(PublicKey publicKey){
		boolean verifySign = false;
		try{
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(this.signPilgrim);
			messageDigest.update(this.dataHostel);
			byte[] hash = messageDigest.digest();
			
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initVerify(publicKey);
			signature.update(hash);
			verifySign = signature.verify(this.signHostel);
		}  catch (NoSuchAlgorithmException e) {
			System.out.println("Error en resumen paquete" + e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return verifySign;
	}
	
	private boolean verifySignPilgrim(PublicKey publicKey){
		boolean verifySign = false;
		try{			
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initVerify(publicKey);
			signature.update(this.dataPilgrim);
			verifySign = signature.verify(this.signPilgrim);
		}  catch (NoSuchAlgorithmException e) {
			System.out.println("Error en resumen paquete" + e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return verifySign;
		
		
	}
	
	private SecretKey decryptSecretKey(byte[] cipherSecretKey) {
		byte[] buffer=null;
		SecretKey secretKey = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			//buffer = cipher.update(cipherSecretKey);
			buffer = cipher.doFinal(cipherSecretKey);
			SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
			DESKeySpec DESspec = new DESKeySpec(buffer);
			secretKey = secretKeyFactoryDES.generateSecret(DESspec);
		}
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
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return secretKey;
	}
	
	private byte[] decrytpData(byte[] data, SecretKey secretKey){
		Cipher cipher;
		byte[] toret=null;
		
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			//toret = cipher.update(data);
			toret = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return toret;
	}
}
